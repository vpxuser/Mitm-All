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

	DB, err = gorm.Open(sqlite.Open(setting.Config.DB.Disk.Path), &gorm.Config{
		Logger: LogFunc[setting.Config.DB.Disk.LogSwitch],
	})
	if err != nil {
		yaklog.Fatalf("Open SQLite Failed : %v", err)
	}

	yaklog.Info("SQLite Connection Established Successfully.")

	err = DB.AutoMigrate(
		//&models.IPMapping{},
		&models.DomainMapping{},
		&models.CertMapping{},
	)
	if err != nil {
		yaklog.Fatalf("SQLite Migrate Failed : %v", err)
	}

	yaklog.Info("SQLite Migration Completed Successfully.")
}
