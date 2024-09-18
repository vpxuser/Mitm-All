package services

import (
	"errors"
	"gorm.io/gorm"
	"socks2https/database"
	"socks2https/models"
)

// getWildcardDomain 获取指定域名的通配符域名
func getWildcardDomain(db *gorm.DB, domain string) (string, error) {
	var mapping models.DomainMapping
	result := db.Where("domain = ?", domain).First(&mapping)

	if result.Error != nil {
		return "", result.Error
	}

	return mapping.WildcardDomain, nil
}

func GetWildcardDomain(domain string) (string, error) {
	wildcardDomain, err := getWildcardDomain(database.Cache, domain)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		wildcardDomain, err = getWildcardDomain(database.DB, domain)
		if err != nil {
			return "", err
		}
		if err = addDomainMapping(database.Cache, domain, wildcardDomain); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return wildcardDomain, nil
}

// addDomainMapping 添加域名到通配符域名的映射关系
func addDomainMapping(db *gorm.DB, domain, wildcardDomain string) error {
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

func AddDomainMapping(domain, wildcardDomain string) error {
	if err := addDomainMapping(database.Cache, domain, wildcardDomain); err != nil {
		return err
	}
	if err := addDomainMapping(database.DB, domain, wildcardDomain); err != nil {
		return err
	}
	return nil
}
