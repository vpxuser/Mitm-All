package tlshandler

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
	"socks2https/context"
	"socks2https/database"
	"socks2https/pkg/certutils"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/tlsutils"
	"socks2https/services"
	"socks2https/setting"
	"strings"
)

var WriteCertificate = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Certificate"))
	var realCert *x509.Certificate
	wildcardDomain, err := services.GetWildcardDomain(database.DB, ctx.TLSContext.SNI)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		realCert, err = certutils.GetRealCertificateWithTCP(ctx.TLSContext.SNI)
		if err != nil {
			yaklog.Errorf("%s %v", tamplate, err)
			return err
		}
		wildcardDomain = ctx.TLSContext.SNI
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
		if err = services.AddDomainMapping(database.DB, ctx.TLSContext.SNI, wildcardDomain); err != nil {
			yaklog.Errorf("Creating Domain Mapping Failed : %v", err)
			return err
		}
	} else if err != nil {
		yaklog.Errorf("%s Failed to Get Wildcard Domain : %v", tamplate, err)
		return err
	}

	ctx.TLSContext.CertDER, ctx.TLSContext.KeyDER, err = services.GetCertAndKey(database.DB, wildcardDomain)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if realCert == nil {
			realCert, err = certutils.GetRealCertificateWithTCP(ctx.TLSContext.SNI)
			if err != nil {
				yaklog.Errorf("%s %v", tamplate, err)
				return err
			}
		}

		ctx.TLSContext.KeyDER, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			yaklog.Errorf("Creating Fake Private Key Failed : %v", err)
			return err
		}
		ctx.TLSContext.CertDER, err = certutils.CreateFakeCertificate(setting.CACert, setting.CAKey, realCert, ctx.TLSContext.KeyDER)
		if err != nil {
			yaklog.Errorf("%s %v", tamplate, err)
			return err
		}
		if err := services.AddCertMapping(database.DB, wildcardDomain, ctx.TLSContext.CertDER, ctx.TLSContext.KeyDER); err != nil {
			yaklog.Errorf("Creating Cert Mapping Failed : %v", err)
			return err
		}
	} else if err != nil {
		yaklog.Errorf("%s Failed to Get Certificate And Private Key : %v", tamplate, err)
		return err
	}

	record, err := tlsutils.NewCertificate(ctx.TLSContext.Version, []*x509.Certificate{ctx.TLSContext.CertDER})
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}
	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, record.Fragment)
	if _, err = conn.Write(record.GetRaw()); err != nil {
		yaklog.Errorf("%s Write Certificate Failed : %v", tamplate, err)
		return err
	}
	yaklog.Infof("%s Write Certificate Successfully.", tamplate)
	return nil
})
