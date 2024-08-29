package mitm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
	"socks2https/pkg/crypt"
	"time"
)

// TLS 常见消息类型
const (
	ContentTypeChangeCipherSpec uint8 = 20 // 0x14 用于更改密码规范消息
	ContentTypeAlert            uint8 = 21 // 0x15 用于警报消息
	ContentTypeHandshake        uint8 = 22 // 0x16 用于握手消息
	ContentTypeApplicationData  uint8 = 23 // 0x17 用于应用数据
	ContentTypeHeartbeat        uint8 = 24 // 0x18 用于心跳消息（仅适用于某些版本）
)

// TLS 不常见消息类型
const (
	ContentTypeTLSPlaintext        uint8 = 0    // 明文TLS数据，未加密 (非正式标准)
	ContentTypeTLSInnerPlaintext   uint8 = 0xFF // 用于 TLS 1.3 的 InnerPlaintext
	ContentTypeSSL20ClientHello    uint8 = 0x80 // SSL 2.0 ClientHello 消息类型
	ContentTypeCompressed          uint8 = 0x19 // 用于压缩的 TLS 数据
	ContentTypeEncryptedExtensions uint8 = 0x08 // TLS 1.3 扩展，安全后协商内容
	ContentTypeSupplementalData    uint8 = 0x0C // 补充数据消息 (SSL 3.0/TLS 1.0)
	ContentTypeCustomExperimental  uint8 = 0xE0 // 实验性自定义消息类型
)

// TLS 版本
const (
	VersionSSL30 uint16 = 0x0300 // SSL 3.0
	VersionTLS10 uint16 = 0x0301 // TLS 1.0
	VersionTLS11 uint16 = 0x0302 // TLS 1.1
	VersionTLS12 uint16 = 0x0303 // TLS 1.2
	VersionTLS13 uint16 = 0x0304 // TLS 1.3
)

var ContentType = map[uint8]string{
	ContentTypeChangeCipherSpec:    "Change Cipher Spec",
	ContentTypeAlert:               "Alert",
	ContentTypeHandshake:           "Handshake",
	ContentTypeApplicationData:     "ApplicationData",
	ContentTypeHeartbeat:           "Heartbeat",
	ContentTypeTLSPlaintext:        "TLS Plaintext",
	ContentTypeTLSInnerPlaintext:   "TLS Inner Plaintext",
	ContentTypeSSL20ClientHello:    "SSL20 ClientHello",
	ContentTypeCompressed:          "Compressed",
	ContentTypeEncryptedExtensions: "Encrypted Extensions",
	ContentTypeSupplementalData:    "Supplemental Data",
	ContentTypeCustomExperimental:  "Custom Experimental",
}

var Version = map[uint16]string{
	VersionSSL30: "TLS Version SSL30",
	VersionTLS10: "TLS Version TLS10",
	VersionTLS11: "TLS Version TLS11",
	VersionTLS12: "TLS Version TLS12",
	VersionTLS13: "TLS Version TLS13",
}

type Record struct {
	ContentType      uint8     `json:"contentType"` //1 byte
	Version          uint16    `json:"version"`     //2 byte
	Length           uint16    `json:"length"`      //2 byte
	Handshake        Handshake `json:"handshake"`
	ChangeCipherSpec uint8     `json:"changeCipherSpec"`
	Fragment         []byte    `json:"fragment"`
}

func ParseRecord(data []byte, ctx *Context) (*Record, error) {
	reader := bytes.NewReader(data)
	record := &Record{}
	if err := binary.Read(reader, binary.BigEndian, &record.ContentType); err != nil {
		return nil, fmt.Errorf("parse TLS Record Content Type failed: %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &record.Version); err != nil {
		return nil, fmt.Errorf("parse TLS Record Version failed: %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &record.Length); err != nil {
		return nil, fmt.Errorf("parse TLS Record Length failed: %v", err)
	}
	if len(data) < 5+int(record.Length) {
		return nil, fmt.Errorf("TLS Record Fragment is incomplete")
	}
	record.Fragment = data[5 : 5+record.Length]
	switch record.ContentType {
	case ContentTypeHandshake:
		handshake, err := ParseHandshake(record.Fragment, ctx)
		if err != nil {
			return nil, fmt.Errorf("parse Handshake failed: %v", err)
		}
		record.Handshake = *handshake
	case ContentTypeChangeCipherSpec:
		record.ChangeCipherSpec = 0x01
	}
	return record, nil
}

func (r *Record) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, r.Version)
	record := append([]byte{r.ContentType}, version...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, r.Length)
	record = append(record, length...)
	if len(r.Fragment) == 0 {
		switch r.ContentType {
		case ContentTypeHandshake:
			return append(record, r.Handshake.GetRaw()...)
		default:
			break
		}
	}
	return append(record, r.Fragment...)
}

func (r *Record) GetDomain() (string, bool) {
	for _, extension := range r.Handshake.ClientHello.Extensions {
		if extension.Type == ExtensionTypeServerName {
			list := extension.ServerName.List
			if len(list) > 0 {
				return list[0].Name, true
			}
		}
	}
	return "", false
}

func NewServerHello(c *Record, ctx *Context) (*Record, error) {
	//serverHello := &ServerHello{Version: c.Handshake.ClientHello.Version}
	serverHello := &ServerHello{Version: ctx.Version}
	binary.BigEndian.PutUint32(serverHello.Random[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(serverHello.Random[4:]); err != nil {
		return nil, fmt.Errorf("generate Random field failed: %v", err)
	}
	serverHello.SessionIDLength = 32
	serverHello.SessionID = make([]byte, serverHello.SessionIDLength)
	if _, err := rand.Read(serverHello.SessionID); err != nil {
		return nil, fmt.Errorf("generate SessionID failed: %v", err)
	}
	returnSwitch := true
	for _, cipherSuite := range c.Handshake.ClientHello.CipherSuites {
		if cipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA {
			returnSwitch = false
			serverHello.CipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA
			break
		}
	}
	if returnSwitch {
		return nil, fmt.Errorf("no supported CipherSuites found")
	}
	serverHello.CompressionMethod = 0
	serverHello.ExtensionsLength = 0
	serverHelloRaw := serverHello.GetRaw()
	handshake := &Handshake{
		HandshakeType: HandshakeTypeServerHello,
		Length:        uint32(len(serverHelloRaw)),
		ServerHello:   *serverHello,
		Payload:       serverHelloRaw,
	}
	handshakeRaw := handshake.GetRaw()
	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}
	return record, nil
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
	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}
	return record, nil
}

func NewServerHelloDone(ctx *Context) *Record {
	handshake := &Handshake{
		HandshakeType: HandshakeTypeServerHelloDone,
		Length:        0,
	}
	handshakeRaw := handshake.GetRaw()
	//yaklog.Debugf("handshake raw: %s", comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%v", handshakeRaw)))
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}
}

func NewFinished(ctx *Context) (*Record, error) {
	hash := ctx.HashFunc()
	hash.Write(comm.Combine(ctx.HandshakeRawList))
	clientKeyExchange := ctx.ClientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	verifyData := PRF(clientKeyExchange.MasterSecret, []byte(LabelServerFinished), hash.Sum(nil), 12)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	chiperVerifyData, err := crypt.EncryptAESCBC(verifyData, clientKeyExchange.ServerKey, clientKeyExchange.ServerIV)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Chiper Verify Data Length : %d , Chiper Verify Data: %v", len(chiperVerifyData), chiperVerifyData)))
	if err != nil {
		return nil, err
	}
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(chiperVerifyData)),
		Fragment:    chiperVerifyData,
	}, nil
}
