package initializers

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var err error

// var DB = initializers.ConnectToDb()
// var DSN = "sql6584688:8NtvpkcXWg@tcp(sql6.freesqldatabase.com:3306)/sql6584688?charset=utf8mb4&parseTime=True&loc=Local"
//var DSN = "ltbwqODtnJ:XS3bkyXm0Z@tcp(remotemysql.com:3306)/ltbwqODtnJ?charset=utf8mb4&parseTime=True&loc=Local"

var DSN = "freedb_Office360:H!d6jZ*$e8kvYm@@tcp(sql.freedb.tech)/freedb_report?charset=utf8mb4&parseTime=True&loc=Local"

func ConnectToDb() *gorm.DB {

	DB, err = gorm.Open(mysql.Open(DSN), &gorm.Config{})
	if err != nil {
		panic("DB NOT CONNECTED")
	}
	return DB
}
