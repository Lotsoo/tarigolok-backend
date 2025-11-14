package main

import (
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Request payloads
type registerReq struct {
	Username string `json:"username" binding:"required,alphanum"`
	Password string `json:"password" binding:"required,min=6"`
	Name     string `json:"name"`
	Email    string `json:"email" binding:"omitempty,email"`
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
		Email:        strings.ToLower(req.Email),
		PasswordHash: string(hashed),
		Name:         req.Name,
		Role:         "user",
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "name": user.Name}})
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
	c.JSON(http.StatusOK, gin.H{"access_token": token, "user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "role": user.Role}})
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
	sub.UpdatedAt = time.Now()
	if err := db.Save(&sub).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sub)
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
