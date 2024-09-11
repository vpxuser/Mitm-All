package services

import (
	"gorm.io/gorm"
	"socks2https/models"
)

// GetWildcardDomain 获取指定域名的通配符域名
func GetWildcardDomain(db *gorm.DB, domain string) (string, error) {
	var mapping models.DomainMapping
	result := db.Where("domain = ?", domain).First(&mapping)

	if result.Error != nil {
		return "", result.Error
	}

	return mapping.WildcardDomain, nil
}

// AddDomainMapping 添加域名到通配符域名的映射关系
func AddDomainMapping(db *gorm.DB, domain, wildcardDomain string) error {
	mapping := models.DomainMapping{
		Domain:         domain,
		WildcardDomain: wildcardDomain,
	}

	result := db.Create(&mapping)
	if result.Error != nil {
		return result.Error
	}

	return nil
}
