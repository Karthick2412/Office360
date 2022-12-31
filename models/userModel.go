package models

type User struct {
	Id       string `gorm:"type:varchar(36);primaryKey;unique" json:"id"`
	Name     string `gorm:"type:varchar(20);not null" json:"name"`
	Email    string `gorm:"type:varchar(30);unique;not null" json:"email"`
	Password string `gorm:"type:varchar(250);not null" json:"password"`
}
