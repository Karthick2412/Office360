package models

import "time"

type PasswordReset struct {
	RequestId   string    `gorm:"type:varchar(36);primaryKey;unique;column:request_id" json:"request_id"`
	UserId      string    `gorm:"type:varchar(36);column:user_id" json:"user_id"`
	OTP         string    `gorm:"type:varchar(6);column:otp" json:"otp"`
	RequestedAt time.Time `gorm:"type:DATETIME;column:requested_at;" json:"requested_at"`
	Status      int       `gorm:"type:varchar(36);column:status" json:"status"`
}
