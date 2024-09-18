package services

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"socks2https/database"
	"socks2https/models"
)

// getCertAndKey 获取指定通配符域名的证书和私钥
func getCertAndKey(db *gorm.DB, wildcardDomain string) ([]byte, []byte, error) {
	var certMapping models.CertMapping
	result := db.Where("wildcard_domain = ?", wildcardDomain).First(&certMapping)

	if result.Error != nil {
		return nil, nil, result.Error
	}

	return certMapping.Certificate, certMapping.PrivateKey, nil
}

func GetCertAndKey(wildcardDomain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certRAW, keyRAW, err := getCertAndKey(database.Cache, wildcardDomain)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		certRAW, keyRAW, err = getCertAndKey(database.Cache, wildcardDomain)
		if err != nil {
			return nil, nil, err
		}
		if err = addCertMapping(database.Cache, wildcardDomain, certRAW, keyRAW); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	certDER, err := x509.ParseCertificate(certRAW)
	if err != nil {
		return nil, nil, fmt.Errorf("Parsing Certificate Failed : %v", err)
	}
	keyDER, err := x509.ParsePKCS1PrivateKey(keyRAW)
	if err != nil {
		return nil, nil, fmt.Errorf("Parsing Private Key Failed : %v", err)
	}
	return certDER, keyDER, nil
}

// addCertMapping 添加通配符域名到证书和私钥的映射关系
func addCertMapping(db *gorm.DB, wildcardDomain string, cert, key []byte) error {
	certMapping := models.CertMapping{
		WildcardDomain: wildcardDomain,
		Certificate:    cert,
		PrivateKey:     key,
	}

	result := db.Create(&certMapping)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func AddCertMapping(wildcardDomain string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	certRAW := cert.Raw
	keyRAW := x509.MarshalPKCS1PrivateKey(key)
	if err := addCertMapping(database.Cache, wildcardDomain, certRAW, keyRAW); err != nil {
		return err
	}
	if err := addCertMapping(database.DB, wildcardDomain, certRAW, keyRAW); err != nil {
		return err
	}
	return nil
}
