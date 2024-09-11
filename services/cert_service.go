package services

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"gorm.io/gorm"
	"socks2https/models"
)

// GetCertAndKey 获取指定通配符域名的证书和私钥
func GetCertAndKey(db *gorm.DB, wildcardDomain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certMapping models.CertMapping
	result := db.Where("wildcard_domain = ?", wildcardDomain).First(&certMapping)

	if result.Error != nil {
		return nil, nil, result.Error
	}

	certDER, err := x509.ParseCertificate(certMapping.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("Parsing Certificate Failed : %v", err)
	}
	keyDER, err := x509.ParsePKCS1PrivateKey(certMapping.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Parsing Private Key Failed : %v", err)
	}
	return certDER, keyDER, nil
}

// AddCertMapping 添加通配符域名到证书和私钥的映射关系
func AddCertMapping(db *gorm.DB, wildcardDomain string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	certMapping := models.CertMapping{
		WildcardDomain: wildcardDomain,
		Certificate:    cert.Raw,
		PrivateKey:     x509.MarshalPKCS1PrivateKey(key),
	}

	result := db.Create(&certMapping)
	if result.Error != nil {
		return result.Error
	}

	return nil
}
