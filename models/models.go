package models

type IPMapping struct {
	ID     uint   `gorm:"primaryKey;autoIncrement"`
	IP     string `gorm:"not null"`
	Domain string `gorm:"not null"`
}

type DomainMapping struct {
	ID             uint   `gorm:"primaryKey;autoIncrement"`
	Domain         string `gorm:"unique;not null"`
	WildcardDomain string `gorm:"not null"`
}

type CertMapping struct {
	ID             uint   `gorm:"primaryKey;autoIncrement"`
	WildcardDomain string `gorm:"unique;not null"`
	Certificate    []byte `gorm:"not null"` // 存储证书
	PrivateKey     []byte `gorm:"not null"` // 存储私钥
}
