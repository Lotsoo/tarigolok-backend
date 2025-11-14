package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println(".env not found, reading environment variables directly")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate models (for quick start). Replace with migration tool for production.
	if err := db.AutoMigrate(&User{}, &Video{}, &Submission{}); err != nil {
		log.Fatalf("AutoMigrate error: %v", err)
	}

	// Seed default users if not present (admin and regular user)
	if err := seedDefaultUsers(db); err != nil {
		log.Fatalf("failed to seed users: %v", err)
	}

	r := gin.Default()

	// public
	r.POST("/api/v1/auth/register", func(c *gin.Context) { RegisterHandler(c, db) })
	r.POST("/api/v1/auth/login", func(c *gin.Context) { LoginHandler(c, db) })

	// protected routes
	api := r.Group("/api/v1")
	api.Use(JWTMiddleware(db))
	{
		api.GET("/videos", func(c *gin.Context) { ListVideosHandler(c, db) })
		api.POST("/videos", AdminOnly(func(c *gin.Context) { CreateVideoHandler(c, db) }))
		api.PUT("/videos/:id", AdminOnly(func(c *gin.Context) { UpdateVideoHandler(c, db) }))
		api.DELETE("/videos/:id", AdminOnly(func(c *gin.Context) { DeleteVideoHandler(c, db) }))

		api.POST("/submissions", func(c *gin.Context) { CreateSubmissionHandler(c, db) })
		api.GET("/submissions", AdminOrOwnerList(func(c *gin.Context) { ListSubmissionsHandler(c, db) }))
		api.GET("/submissions/:id", AdminOnly(func(c *gin.Context) { GetSubmissionHandler(c, db) }))
		api.POST("/submissions/:id/feedback", AdminOnly(func(c *gin.Context) { FeedbackHandler(c, db) }))
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	bind := os.Getenv("BIND_ADDR")
	if bind == "" {
		bind = "0.0.0.0"
	}

	srv := &http.Server{
		Addr:    bind + ":" + port,
		Handler: r,
	}
	// Print discovered non-loopback IPv4 addresses with port so it's easy to
	// see which IPs the server is reachable at from LAN devices.
	ips := []string{}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue // interface down
			}
			if iface.Flags&net.FlagLoopback != 0 {
				continue // skip loopback
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ip = ip.To4()
				if ip == nil {
					continue // not an ipv4 address
				}
				ips = append(ips, ip.String())
			}
		}
	}
	if len(ips) == 0 {
		// Fallback to bind address
		ips = append(ips, bind)
	}
	for _, ip := range ips {
		log.Printf("listening on http://%s:%s", ip, port)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func seedDefaultUsers(db *gorm.DB) error {
	// Create admin and user with default passwords if they don't exist
	var count int64
	db.Model(&User{}).Where("username = ?", "admin").Count(&count)
	if count == 0 {
		// create admin
		pass := os.Getenv("DEFAULT_ADMIN_PASSWORD")
		if pass == "" {
			pass = "adminpass"
		}
		hashed, err := hashPassword(pass)
		if err != nil {
			return err
		}
		admin := User{
			Username:     "admin",
			Email:        "admin@example.com",
			PasswordHash: string(hashed),
			Name:         "Administrator",
			Role:         "admin",
		}
		if err := db.Create(&admin).Error; err != nil {
			return err
		}
		log.Printf("seeded admin user: username=admin password=%s", pass)
	}

	db.Model(&User{}).Where("username = ?", "user").Count(&count)
	if count == 0 {
		pass := os.Getenv("DEFAULT_USER_PASSWORD")
		if pass == "" {
			pass = "userpass"
		}
		hashed, err := hashPassword(pass)
		if err != nil {
			return err
		}
		u := User{
			Username:     "user",
			Email:        "user@example.com",
			PasswordHash: string(hashed),
			Name:         "Regular User",
			Role:         "user",
		}
		if err := db.Create(&u).Error; err != nil {
			return err
		}
		log.Printf("seeded regular user: username=user password=%s", pass)
	}
	return nil
}

func hashPassword(password string) ([]byte, error) {
	cost := 12
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cost = n
		}
	}
	return bcrypt.GenerateFromPassword([]byte(password), cost)
}
