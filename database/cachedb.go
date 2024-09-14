package database

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"socks2https/models"
	"socks2https/setting"
)

var Cache *gorm.DB

var LogFunc = map[bool]logger.Interface{
	true:  logger.Default,
	false: logger.Discard,
}

func init() {

	var err error

	Cache, err = gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: LogFunc[setting.Config.DB.Cache.LogSwitch],
	})
	if err != nil {
		yaklog.Fatalf("Open In-Memory SQLite Failed : %v", err)
	}

	yaklog.Infof("In-memory SQLite Connected Established Successfully.")

	if err = Cache.AutoMigrate(&models.IPMapping{}); err != nil {
		yaklog.Fatalf("Database Migration Failed : %v", err)
	}

	yaklog.Infof("In-memory SQLite Migrated Completed Successfully.")
}
