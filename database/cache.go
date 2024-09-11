package database

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"socks2https/models"
)

var Cache *gorm.DB

func init() {
	var err error

	Cache, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		yaklog.Fatalf("Open In-Memory Database Failed : %v", err)
	}

	yaklog.Infof("In-memory Database Connected.")

	if err = Cache.AutoMigrate(&models.IPMapping{}); err != nil {
		yaklog.Fatalf("Database Migration Failed : %v", err)
	}

	yaklog.Infof("Cache Table Migrated.")
}
