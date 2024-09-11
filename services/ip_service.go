package services

import (
	"gorm.io/gorm"
	"socks2https/models"
)

// GetDomainByIP 获取指定 IP 对应的域名
func GetDomainByIP(db *gorm.DB, ip string) (string, error) {
	var ipMapping models.IPMapping
	result := db.Where("ip = ?", ip).First(&ipMapping)

	if result.Error != nil {
		return "", result.Error
	}

	return ipMapping.Domain, nil
}

// GetIPByDomain 获取指定 IP 对应的域名
func GetIPByDomain(db *gorm.DB, domain string) (string, error) {
	var ipMapping models.IPMapping
	result := db.Where("domain = ?", domain).First(&ipMapping)

	if result.Error != nil {
		return "", result.Error
	}

	return ipMapping.IP, nil
}

// AddIPMapping 添加 IP 到域名的映射关系
func AddIPMapping(db *gorm.DB, ip, domain string) error {
	ipMapping := models.IPMapping{
		IP:     ip,
		Domain: domain,
	}

	result := db.Create(&ipMapping)
	if result.Error != nil {
		return result.Error
	}

	return nil
}
