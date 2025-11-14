package main

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           string         `gorm:"primaryKey;type:uuid" json:"id"`
	Username     string         `gorm:"uniqueIndex;not null" json:"username"`
	Email        string         `gorm:"uniqueIndex" json:"email"`
	PasswordHash string         `gorm:"not null" json:"-"`
	Name         string         `json:"name"`
	Role         string         `gorm:"type:text;default:'user'" json:"role"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	return nil
}

type Video struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Title       string    `gorm:"not null" json:"title"`
	YoutubeID   string    `gorm:"not null;index" json:"youtube_id"`
	Description string    `json:"description"`
	CreatedByID *string   `gorm:"type:uuid" json:"created_by_id"`
	CreatedAt   time.Time `json:"created_at"`
}

func (v *Video) BeforeCreate(tx *gorm.DB) (err error) {
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	return nil
}

type Submission struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"user_id"`
	Link      string    `gorm:"not null" json:"link"`
	Note      string    `json:"note"`
	Status    string    `gorm:"type:text;default:'pending'" json:"status"`
	Feedback  string    `json:"feedback"`
	AdminID   *string   `gorm:"type:uuid" json:"admin_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Submission) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	return nil
}
