package mitm

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"gorm.io/gorm"
	"net"
	"socks2https/database"
	"socks2https/pkg/certutils"
	"socks2https/pkg/color"
	"socks2https/services"
	"socks2https/setting"
	"strings"
)

type Certificate struct {
	CertificatesLength uint32 `json:"certificatesLength,omitempty"` // 3个字节
	Certificates       []struct {
		CertificateLength uint32 // 3个字节
		Certificate       []byte
	} `json:"certificates,omitempty"`
}

func NewCertificate(version uint16, certDERs []*x509.Certificate) (*Record, error) {
	certificate := &Certificate{}
	for _, certDER := range certDERs {
		certificateLength := uint32(len(certDER.Raw))
		certificate.CertificatesLength += 3 + certificateLength
		certificate.Certificates = append(certificate.Certificates, struct {
			CertificateLength uint32
			Certificate       []byte
		}{CertificateLength: certificateLength, Certificate: certDER.Raw})
	}
	certificateRaw := certificate.GetRaw()
	handshake := &Handshake{
		HandshakeType: HandshakeTypeCertificate,
		Length:        uint32(len(certificateRaw)),
		Certificate:   *certificate,
		Payload:       certificateRaw,
	}
	handshakeRaw := handshake.GetRaw()
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}, nil
}

// ParseCertificate 从 []byte 数据解析出 Certificate 结构体
func ParseCertificate(data []byte) (*Certificate, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("TLS Handshake Data is incomplete")
	}
	offset := 0
	certificatesLength := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	offset += 3
	certificate := &Certificate{CertificatesLength: certificatesLength}
	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, fmt.Errorf("Certificate Entry is invalid")
		}
		certificateLength := uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
		offset += 3
		certificate.Certificates = append(certificate.Certificates, struct {
			CertificateLength uint32
			Certificate       []byte
		}{CertificateLength: certificateLength, Certificate: data[offset : offset+int(certificateLength)]})
		offset += int(certificateLength)
	}
	return certificate, nil
}

func (c *Certificate) GetRaw() []byte {
	certificatesLength := []byte{byte(c.CertificatesLength >> 16), byte(c.CertificatesLength >> 8), byte(c.CertificatesLength)}
	certificates := certificatesLength
	for _, certificate := range c.Certificates {
		certificateLength := []byte{byte(certificate.CertificateLength >> 16), byte(certificate.CertificateLength >> 8), byte(certificate.CertificateLength)}
		certificates = append(certificates, append(certificateLength, certificate.Certificate...)...)
	}
	return certificates
}

var WriteCertificate = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Handshake"), color.SetColor(color.RED_COLOR_TYPE, "Certificate"))
	var realCert *x509.Certificate
	wildcardDomain, err := services.GetWildcardDomain(database.DB, ctx.Domain)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		realCert, err = certutils.GetRealCertificateWithTCP(ctx.Domain)
		if err != nil {
			return err
		}
		wildcardDomain = ctx.Domain
		// 提取 CN 字段中的通配符域名
		if strings.HasPrefix(realCert.Subject.CommonName, "*.") {
			wildcardDomain = realCert.Subject.CommonName
		} else {
			// 提取 SAN 扩展中的 DNS 名称
			for _, dnsName := range realCert.DNSNames {
				if strings.HasPrefix(dnsName, "*.") {
					wildcardDomain = dnsName
					break
				}
			}
		}
		if err = services.AddDomainMapping(database.DB, ctx.Domain, wildcardDomain); err != nil {
			return fmt.Errorf("Creating Domain Mapping Failed : %v", err)
		}
	} else if err != nil {
		return err
	}

	ctx.CertDER, ctx.KeyDER, err = services.GetCertAndKey(database.DB, wildcardDomain)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if realCert == nil {
			realCert, err = certutils.GetRealCertificateWithTCP(ctx.Domain)
			if err != nil {
				return err
			}
		}

		ctx.KeyDER, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("Creating Fake Private Key Failed : %v", err)
		}
		ctx.CertDER, err = certutils.CreateFakeCertificate(setting.CACert, setting.CAKey, realCert, ctx.KeyDER)
		if err != nil {
			return err
		}
		if err := services.AddCertMapping(database.DB, wildcardDomain, ctx.CertDER, ctx.KeyDER); err != nil {
			return fmt.Errorf("Creating Cert Mapping Failed : %v", err)
		}
	} else if err != nil {
		return err
	}

	record, err := NewCertificate(ctx.Version, []*x509.Certificate{ctx.CertDER})
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	if _, err = conn.Write(record.GetRaw()); err != nil {
		return fmt.Errorf("%s Write Certificate Failed : %v", tamplate, err)
	}
	yaklog.Infof("%s Write Certificate Successfully.", tamplate)
	return nil
})
