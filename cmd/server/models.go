package main

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           string         `gorm:"primaryKey;type:uuid" json:"id"`
	Username     string         `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string         `gorm:"not null" json:"-"`
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
	ID       string  `gorm:"primaryKey;type:uuid" json:"id"`
	UserID   string  `gorm:"type:uuid;not null;index" json:"user_id"`
	Link     string  `gorm:"not null" json:"link"`
	Note     string  `json:"note"`
	Status   string  `gorm:"type:text;default:'pending'" json:"status"`
	Feedback string  `json:"feedback"`
	AdminID  *string `gorm:"type:uuid" json:"admin_id"`
	// ReplyRead indicates whether the user has seen the admin's feedback
	ReplyRead bool      `gorm:"default:false" json:"reply_read"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Submission) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	return nil
}

type Schedule struct {
	ID       string `gorm:"primaryKey;type:uuid" json:"id"`
	Title    string `gorm:"not null" json:"title"`
	Date     string `json:"date"`
	Time     string `json:"time"`
	Location string `json:"location"`
	Notes    string `json:"notes"`
	// Structured recurrence fields
	Recurrence string    `json:"recurrence"`
	Weekdays   string    `json:"weekdays"` // comma-separated days when recurrence == Mingguan
	CreatedBy  *string   `gorm:"type:uuid" json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Schedule) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	return nil
}

type Archive struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Title       string    `gorm:"not null" json:"title"`
	Description string    `json:"description"`
	MediaURL    string    `json:"media_url"`
	CreatedBy   *string   `gorm:"type:uuid" json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (a *Archive) BeforeCreate(tx *gorm.DB) (err error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	return nil
}

// Doc represents a documentation entry (Dokumentasi)
type Doc struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Title       string    `gorm:"not null" json:"title"`
	Description string    `json:"description"`
	Link        string    `json:"link"` // optional external link or file URL
	CreatedBy   *string   `gorm:"type:uuid" json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (d *Doc) BeforeCreate(tx *gorm.DB) (err error) {
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	return nil
}
