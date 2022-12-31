package initializers

import (
	"taskupdate/models"
)

func SyncDatabase() {
	ConnectToDb().AutoMigrate(&models.User{})
	ConnectToDb().AutoMigrate(&models.PasswordReset{})
	ConnectToDb().AutoMigrate(&models.Task{})
}
