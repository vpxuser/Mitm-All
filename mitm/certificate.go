package mitm

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
)

type Certificate struct {
	CertificatesLength uint32 `json:"certificatesLength,omitempty"` // 3个字节
	Certificates       []struct {
		CertificateLength uint32 // 3个字节
		Certificate       []byte
	} `json:"certificates,omitempty"`
}

func NewCertificate(path string, ctx *Context) (*Record, error) {
	certDER, keyDER, err := cert.GetCertificateAndKey(path, ctx.Domain)
	if err != nil {
		return nil, err
	}
	ctx.CertDER, ctx.KeyDER = certDER, keyDER
	certificate := &Certificate{
		CertificatesLength: uint32(3 + len(certDER.Raw)),
		Certificates: []struct {
			CertificateLength uint32
			Certificate       []byte
		}{{
			CertificateLength: uint32(len(certDER.Raw)),
			Certificate:       certDER.Raw,
		}},
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
		Version:     ctx.Version,
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
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"), comm.SetColor(comm.RED_COLOR_TYPE, "Certificate"))
	record, err := NewCertificate(ctx.ConfigPath, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	if _, err = conn.Write(record.GetRaw()); err != nil {
		return fmt.Errorf("%s write TLS Record failed : %v", tamplate, err)
	}
	yaklog.Infof("%s write TLS Record Successfully", tamplate)
	return nil
})
