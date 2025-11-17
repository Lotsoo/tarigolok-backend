package main

import (
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Request payloads
type registerReq struct {
	Username string `json:"username" binding:"required,alphanum"`
	Password string `json:"password" binding:"required,min=6"`
}

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterHandler creates a new user (role default: user)
func RegisterHandler(c *gin.Context, db *gorm.DB) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// hash password
	cost := 12
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cost = n
		}
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), cost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := User{
		Username:     strings.ToLower(req.Username),
		PasswordHash: string(hashed),
		Role:         "user",
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": gin.H{"id": user.ID, "username": user.Username, "role": user.Role}})
}

// LoginHandler authenticates user and returns JWT
func LoginHandler(c *gin.Context, db *gorm.DB) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user User
	if err := db.Where("username = ?", strings.ToLower(req.Username)).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := generateJWT(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": token, "user": gin.H{"id": user.ID, "username": user.Username, "role": user.Role}})
}

// MeHandler returns basic profile info for the authenticated user
func MeHandler(c *gin.Context, db *gorm.DB) {
	uidRaw, _ := c.Get("user_id")
	uid, _ := uidRaw.(string)
	var user User
	if err := db.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	// return non-sensitive fields only (no name/email stored anymore)
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username, "role": user.Role})
}

// Videos handlers
type createVideoReq struct {
	Title       string `json:"title" binding:"required"`
	YoutubeID   string `json:"youtube_id" binding:"required"`
	Description string `json:"description"`
}

type updateVideoReq struct {
	Title       string `json:"title" binding:"required"`
	YoutubeID   string `json:"youtube_id" binding:"required"`
	Description string `json:"description"`
}

func ListVideosHandler(c *gin.Context, db *gorm.DB) {
	var videos []Video
	if err := db.Order("created_at desc").Find(&videos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, videos)
}

func CreateVideoHandler(c *gin.Context, db *gorm.DB) {
	var req createVideoReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// normalize youtube id (accept full URL or bare id)
	normalized := normalizeYoutubeID(req.YoutubeID)
	if normalized == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid youtube_id"})
		return
	}
	// get current user ID from context if available
	createdBy, _ := c.Get("user_id")
	var createdByID *string
	if s, ok := createdBy.(string); ok {
		createdByID = &s
	}
	video := Video{
		Title:       req.Title,
		YoutubeID:   normalized,
		Description: req.Description,
		CreatedByID: createdByID,
	}
	if err := db.Create(&video).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, video)
}

func UpdateVideoHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	var req updateVideoReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var video Video
	if err := db.First(&video, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "video not found"})
		return
	}
	// normalize youtube id before saving
	normalized := normalizeYoutubeID(req.YoutubeID)
	if normalized == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid youtube_id"})
		return
	}
	video.Title = req.Title
	video.YoutubeID = normalized
	video.Description = req.Description
	if err := db.Save(&video).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, video)
}

// normalize and extract a YouTube video id from a variety of inputs (full URL or id)
func normalizeYoutubeID(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}
	// find first 11-character id-like substring
	re := regexp.MustCompile(`[A-Za-z0-9_-]{11}`)
	match := re.FindString(s)
	return match
}

func DeleteVideoHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	if err := db.Delete(&Video{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, gin.H{})
}

// Submissions handlers
type createSubmissionReq struct {
	Link string `json:"link" binding:"required,url"`
	Note string `json:"note"`
}

func CreateSubmissionHandler(c *gin.Context, db *gorm.DB) {
	var req createSubmissionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	uidRaw, _ := c.Get("user_id")
	uid, _ := uidRaw.(string)
	sub := Submission{
		UserID: uid,
		Link:   req.Link,
		Note:   req.Note,
		Status: "pending",
	}
	if err := db.Create(&sub).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, sub)
}

func ListSubmissionsHandler(c *gin.Context, db *gorm.DB) {
	roleRaw, _ := c.Get("role")
	role, _ := roleRaw.(string)
	uidRaw, _ := c.Get("user_id")
	uid, _ := uidRaw.(string)

	var subs []Submission
	if role == "admin" {
		if err := db.Order("created_at desc").Find(&subs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		if err := db.Where("user_id = ?", uid).Order("created_at desc").Find(&subs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, subs)
}

func GetSubmissionHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	roleRaw, _ := c.Get("role")
	role, _ := roleRaw.(string)
	uidRaw, _ := c.Get("user_id")
	uid, _ := uidRaw.(string)
	// Log request details for troubleshooting
	// Note: uses standard library log via Printf to ensure visibility in server logs
	// (avoid fmt to keep consistent logging behavior)
	// Example output: GetSubmissionHandler id=<id> user=<uid> role=<role>
	// This helps debug 404s by showing the requested id and caller identity.
	log.Printf("GetSubmissionHandler id=%s user=%s role=%s", id, uid, role)
	var sub Submission
	if err := db.First(&sub, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "submission not found"})
		return
	}
	// Allow admins to view any submission; non-admins may only view their own
	if role != "admin" && sub.UserID != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	// If the caller is the submission owner (non-admin) and there is a reply
	// mark the reply as read so the user will see it as acknowledged.
	if role != "admin" && sub.UserID == uid {
		if sub.Status == "replied" && !sub.ReplyRead {
			sub.ReplyRead = true
			// best-effort save; ignore save error for the response but log it
			if err := db.Save(&sub).Error; err != nil {
				log.Printf("failed to mark submission reply as read id=%s user=%s err=%v", id, uid, err)
			}
		}
	}
	c.JSON(http.StatusOK, sub)
}

type feedbackReq struct {
	Feedback string `json:"feedback" binding:"required"`
}

func FeedbackHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	var req feedbackReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// find submission
	var sub Submission
	if err := db.First(&sub, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "submission not found"})
		return
	}
	adminRaw, _ := c.Get("user_id")
	adminID, _ := adminRaw.(string)

	sub.Feedback = req.Feedback
	sub.Status = "replied"
	sub.AdminID = &adminID
	// Mark as unread for the user (they have not seen the feedback yet)
	sub.ReplyRead = false
	sub.UpdatedAt = time.Now()
	if err := db.Save(&sub).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sub)
}

// Schedule handlers
type createScheduleReq struct {
	Title      string   `json:"title" binding:"required"`
	Date       string   `json:"date"`
	Time       string   `json:"time"`
	Location   string   `json:"location"`
	Notes      string   `json:"notes"`
	Recurrence string   `json:"recurrence"`
	Weekdays   []string `json:"weekdays"`
}

// Archive handlers
type createArchiveReq struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	MediaURL    string `json:"media_url"`
}

type updateArchiveReq struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	MediaURL    string `json:"media_url"`
}

func ListArchivesHandler(c *gin.Context, db *gorm.DB) {
	var list []Archive
	if err := db.Order("created_at desc").Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func CreateArchiveHandler(c *gin.Context, db *gorm.DB) {
	// Support both JSON body (media_url) and multipart/form-data (file upload)
	var title, description, mediaURL string
	// try multipart first
	file, err := c.FormFile("file")
	if err == nil && file != nil {
		// Save uploaded file
		savedURL, saveErr := saveUploadedFile(c, file)
		if saveErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": saveErr.Error()})
			return
		}
		mediaURL = savedURL
		title = c.PostForm("title")
		description = c.PostForm("description")
	} else {
		// fallback to JSON
		var req createArchiveReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		title = req.Title
		description = req.Description
		mediaURL = req.MediaURL
	}

	createdByRaw, _ := c.Get("user_id")
	var createdBy *string
	if s, ok := createdByRaw.(string); ok {
		createdBy = &s
	}
	a := Archive{
		Title:       title,
		Description: description,
		MediaURL:    mediaURL,
		CreatedBy:   createdBy,
	}
	if err := db.Create(&a).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, a)
}

func UpdateArchiveHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	// Support multipart upload or JSON update
	var title, description, mediaURL string
	// try multipart
	file, err := c.FormFile("file")
	if err == nil && file != nil {
		savedURL, saveErr := saveUploadedFile(c, file)
		if saveErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": saveErr.Error()})
			return
		}
		mediaURL = savedURL
		title = c.PostForm("title")
		description = c.PostForm("description")
	} else {
		var req updateArchiveReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		title = req.Title
		description = req.Description
		mediaURL = req.MediaURL
	}

	var a Archive
	if err := db.First(&a, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "archive not found"})
		return
	}
	a.Title = title
	a.Description = description
	if mediaURL != "" {
		a.MediaURL = mediaURL
	}
	if err := db.Save(&a).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, a)
}

// saveUploadedFile saves the uploaded file to the configured upload directory and returns the public URL path
func saveUploadedFile(c *gin.Context, fh *multipart.FileHeader) (string, error) {
	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "./uploads"
	}
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", err
	}
	// simple extension whitelist
	ext := strings.ToLower(filepath.Ext(fh.Filename))
	allowed := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".pdf": true, ".mp4": true}
	if !allowed[ext] {
		return "", fmt.Errorf("file type not allowed: %s", ext)
	}
	// generate unique filename
	fname := uuid.NewString() + ext
	dst := filepath.Join(uploadDir, fname)
	if err := c.SaveUploadedFile(fh, dst); err != nil {
		return "", err
	}
	// return public absolute URL; main.go serves uploadDir at /uploads
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	return fmt.Sprintf("%s://%s/uploads/%s", scheme, host, fname), nil
}

func DeleteArchiveHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	if err := db.Delete(&Archive{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, gin.H{})

}

// Docs (Dokumentasi) handlers
type createDocReq struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	Link        string `json:"link"`
}

type updateDocReq struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	Link        string `json:"link"`
}

func ListDocsHandler(c *gin.Context, db *gorm.DB) {
	var list []Doc
	if err := db.Order("created_at desc").Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func CreateDocHandler(c *gin.Context, db *gorm.DB) {
	var req createDocReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	createdByRaw, _ := c.Get("user_id")
	var createdBy *string
	if s, ok := createdByRaw.(string); ok {
		createdBy = &s
	}
	d := Doc{
		Title:       req.Title,
		Description: req.Description,
		Link:        req.Link,
		CreatedBy:   createdBy,
	}
	if err := db.Create(&d).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, d)
}

func UpdateDocHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	var req updateDocReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var d Doc
	if err := db.First(&d, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "doc not found"})
		return
	}
	d.Title = req.Title
	d.Description = req.Description
	d.Link = req.Link
	if err := db.Save(&d).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, d)
}

func DeleteDocHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	if err := db.Delete(&Doc{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, gin.H{})
}

type updateScheduleReq struct {
	Title      string   `json:"title" binding:"required"`
	Date       string   `json:"date"`
	Time       string   `json:"time"`
	Location   string   `json:"location"`
	Notes      string   `json:"notes"`
	Recurrence string   `json:"recurrence"`
	Weekdays   []string `json:"weekdays"`
}

func ListSchedulesHandler(c *gin.Context, db *gorm.DB) {
	var list []Schedule
	if err := db.Order("created_at desc").Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// return weekdays as structured array for API consumers
	out := make([]map[string]interface{}, 0, len(list))
	for _, s := range list {
		var days []string
		if strings.TrimSpace(s.Weekdays) != "" {
			parts := strings.Split(s.Weekdays, ",")
			for _, p := range parts {
				if t := strings.TrimSpace(p); t != "" {
					days = append(days, t)
				}
			}
		}
		out = append(out, gin.H{
			"id":         s.ID,
			"title":      s.Title,
			"date":       s.Date,
			"time":       s.Time,
			"location":   s.Location,
			"notes":      s.Notes,
			"recurrence": s.Recurrence,
			"weekdays":   days,
			"created_by": s.CreatedBy,
			"created_at": s.CreatedAt,
			"updated_at": s.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

func CreateScheduleHandler(c *gin.Context, db *gorm.DB) {
	var req createScheduleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	createdByRaw, _ := c.Get("user_id")
	var createdBy *string
	if s, ok := createdByRaw.(string); ok {
		createdBy = &s
	}
	// persist weekdays as comma-separated string
	weekdaysStr := ""
	if len(req.Weekdays) > 0 {
		weekdaysStr = strings.Join(req.Weekdays, ",")
	}
	sch := Schedule{
		Title:      req.Title,
		Date:       req.Date,
		Time:       req.Time,
		Location:   req.Location,
		Notes:      req.Notes,
		Recurrence: req.Recurrence,
		Weekdays:   weekdaysStr,
		CreatedBy:  createdBy,
	}
	if err := db.Create(&sch).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// return structured response (weekdays as array)
	var outDays []string
	if strings.TrimSpace(sch.Weekdays) != "" {
		for _, p := range strings.Split(sch.Weekdays, ",") {
			if t := strings.TrimSpace(p); t != "" {
				outDays = append(outDays, t)
			}
		}
	}
	resp := gin.H{
		"id":         sch.ID,
		"title":      sch.Title,
		"date":       sch.Date,
		"time":       sch.Time,
		"location":   sch.Location,
		"notes":      sch.Notes,
		"recurrence": sch.Recurrence,
		"weekdays":   outDays,
		"created_by": sch.CreatedBy,
		"created_at": sch.CreatedAt,
		"updated_at": sch.UpdatedAt,
	}
	c.JSON(http.StatusCreated, resp)
}

func UpdateScheduleHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	var req updateScheduleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var sch Schedule
	if err := db.First(&sch, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "schedule not found"})
		return
	}
	sch.Title = req.Title
	sch.Date = req.Date
	sch.Time = req.Time
	sch.Location = req.Location
	sch.Notes = req.Notes
	sch.Recurrence = req.Recurrence
	if len(req.Weekdays) > 0 {
		sch.Weekdays = strings.Join(req.Weekdays, ",")
	} else {
		sch.Weekdays = ""
	}
	if err := db.Save(&sch).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// build structured response
	var outDays []string
	if strings.TrimSpace(sch.Weekdays) != "" {
		for _, p := range strings.Split(sch.Weekdays, ",") {
			if t := strings.TrimSpace(p); t != "" {
				outDays = append(outDays, t)
			}
		}
	}
	resp := gin.H{
		"id":         sch.ID,
		"title":      sch.Title,
		"date":       sch.Date,
		"time":       sch.Time,
		"location":   sch.Location,
		"notes":      sch.Notes,
		"recurrence": sch.Recurrence,
		"weekdays":   outDays,
		"created_by": sch.CreatedBy,
		"created_at": sch.CreatedAt,
		"updated_at": sch.UpdatedAt,
	}
	c.JSON(http.StatusOK, resp)
}

func DeleteScheduleHandler(c *gin.Context, db *gorm.DB) {
	id := c.Param("id")
	if err := db.Delete(&Schedule{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusNoContent, gin.H{})
}

// Helper wrapper types
func AdminOnly(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleRaw, _ := c.Get("role")
		role, _ := roleRaw.(string)
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin only"})
			return
		}
		next(c)
	}
}

func AdminOrOwnerList(next gin.HandlerFunc) gin.HandlerFunc {
	// no-op wrapper: ListSubmissionsHandler checks role internally
	return func(c *gin.Context) { next(c) }
}

// JWT generation
func generateJWT(userID string, role string) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev_secret"
	}
	claims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// JWTMiddleware parses token and sets user_id and role in context
func JWTMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}
		tokenStr := parts[1]
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			secret = "dev_secret"
		}
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			sub, _ := claims["sub"].(string)
			role, _ := claims["role"].(string)
			c.Set("user_id", sub)
			c.Set("role", role)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
	}
}
