package database

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"socks2https/models"
	"socks2https/setting"
)

var DB *gorm.DB

func init() {
	var err error

	DB, err = gorm.Open(sqlite.Open(setting.Config.DB.Path), &gorm.Config{})
	if err != nil {
		yaklog.Fatalf("Open Database Failed : %v", err)
	}

	yaklog.Info("Database Connection Established Successfully.")

	err = DB.AutoMigrate(
		//&models.IPMapping{},
		&models.DomainMapping{},
		&models.CertMapping{},
	)
	if err != nil {
		yaklog.Fatalf("Database Migrate Failed : %v", err)
	}

	yaklog.Info("Database Migration Completed Successfully.")
}
