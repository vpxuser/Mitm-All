package mitm

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	VersionSSL300 uint16 = 0x0300 // SSL 3.0
	VersionTLS100 uint16 = 0x0301 // TLS 1.0
	VersionTLS101 uint16 = 0x0302 // TLS 1.1
	VersionTLS102 uint16 = 0x0303 // TLS 1.2
	VersionTLS103 uint16 = 0x0304 // TLS 1.3
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

type TLSPlaintext struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Fragment    []byte
}

type TLSCompressed struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Fragment    []byte
}

type TLSCiphertext struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Fragment    []byte
}

var Version = map[uint16]string{
	VersionSSL300: "TLS Version SSL 3.0",
	VersionTLS100: "TLS Version TLS 1.0",
	VersionTLS101: "TLS Version TLS 1.1",
	VersionTLS102: "TLS Version TLS 1.2",
	VersionTLS103: "TLS Version TLS 1.3",
}

type Record struct {
	ContentType      uint8            `json:"contentType"` //1 byte
	Version          uint16           `json:"version"`     //2 byte
	Length           uint16           `json:"length"`      //2 byte
	Fragment         []byte           `json:"fragment,omitempty"`
	Handshake        Handshake        `json:"handshake,omitempty"`
	ChangeCipherSpec ChangeCipherSpec `json:"changeCipherSpec,omitempty"`
	Alert            Alert            `json:"alert,omitempty"`
}

func NewBlockRecord(record *Record, ctx *Context) ([]byte, error) {
	seqNum := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNum, ctx.ServerSeqNum)
	mac := crypt.HmacHash(ctx.ServerMACKey, append(seqNum, record.GetRaw()...), ctx.HashFunc)
	plainFragment := append(record.Fragment, mac...)
	ctx.ServerSeqNum++
	paddingLength := ctx.BlockLength - len(plainFragment)%ctx.BlockLength
	padding := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
	cipherFragment, err := crypt.AESCBCEncrypt(append(plainFragment, append(mac, append(padding, byte(paddingLength))...)...), ctx.ServerKey, ctx.ServerIV)
	if err != nil {
		return nil, err
	}
	finalFragment := append(ctx.ServerIV, cipherFragment...)
	blockRecord := &Record{
		ContentType: record.ContentType,
		Version:     record.Version,
		Length:      uint16(len(finalFragment)),
		Fragment:    finalFragment,
	}
	return blockRecord.GetRaw(), nil
}

func (r *Record) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, r.Version)
	record := append([]byte{r.ContentType}, version...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, r.Length)
	record = append(record, length...)
	if r.Fragment == nil {
		switch r.ContentType {
		case ContentTypeHandshake:
			return append(record, r.Handshake.GetRaw()...)
		case ContentTypeChangeCipherSpec:
			return append(record, r.ChangeCipherSpec.GetRaw()...)
		case ContentTypeAlert:
			return append(record, r.Alert.GetRaw()...)
		default:
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("not support Content Type : %v", r.ContentType)))
		}
	}
	return append(record, r.Fragment...)
}

func ParseBlockRecord(blockRecord []byte, ctx *Context) (*Record, error) {
	plainRecord := blockRecord[:3]
	iv := blockRecord[5 : 5+ctx.BlockLength]
	paddingFragment, err := crypt.AESCBCDecrypt(blockRecord[5+ctx.BlockLength:], ctx.ClientKey, iv)
	if err != nil {
		return nil, err
	}
	paddingLength := paddingFragment[len(paddingFragment)-1]
	plainFragment := paddingFragment[:len(paddingFragment)-int(paddingLength)-1]
	fragment, mac := plainFragment[:len(plainFragment)-ctx.MACLength], plainFragment[len(plainFragment)-ctx.MACLength:]
	fragmentLength := make([]byte, 2)
	binary.BigEndian.PutUint16(fragmentLength, uint16(len(fragment)))
	plainRecord = append(plainRecord, append(fragmentLength, fragment...)...)
	seqNum := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNum, ctx.ClientSeqNum)
	verifyMAC := crypt.HmacHash(ctx.ClientMACKey, append(seqNum, plainRecord...), ctx.HashFunc)
	ctx.ClientSeqNum++
	//todo
	if !hmac.Equal(mac, verifyMAC) {
		yaklog.Debugf("Verify MAC Successful")
	} else {
		yaklog.Debugf("Verify MAC Failed")
	}
	record, err := ParseRecord(plainRecord, ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func ParseRecord(data []byte, ctx *Context) (*Record, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS Record is invaild")
	}
	record := &Record{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
		Length:      binary.BigEndian.Uint16(data[3:5]),
	}
	if len(data) != 5+int(record.Length) {
		return nil, fmt.Errorf("TLS Record Fragment is incomplete")
	}
	record.Fragment = data[5 : 5+record.Length]
	switch record.ContentType {
	case ContentTypeHandshake:
		handshake, err := ParseHandshake(record.Fragment, ctx)
		if err != nil {
			return nil, err
		}
		record.Handshake = *handshake
	case ContentTypeChangeCipherSpec:
		changeCipherSpec, err := ParseChangeCipherSpec(data[5+record.Length:])
		if err != nil {
			return nil, err
		}
		record.ChangeCipherSpec = *changeCipherSpec
	case ContentTypeAlert:
		alert, err := ParseAlert(record.Fragment, ctx)
		if err != nil {
			return nil, err
		}
		record.Alert = *alert
	}
	return record, nil
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

func NewChangeCipherSpec() *Record {
	return &Record{
		ContentType: ContentTypeChangeCipherSpec,
		Version:     VersionTLS102,
		Length:      1,
		Fragment:    []byte{0x01},
	}
}

func NewFinished(label string, ctx *Context) *Record {
	clientKeyExchange := ctx.ClientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	yaklog.Debugf("Handshake Messages Length : %d", len(ctx.HandshakeMessages))
	for i, h := range ctx.HandshakeMessages {
		yaklog.Debugf("Handshake Messages %d : %v", i, h)
	}
	verifyData := PRF(clientKeyExchange.MasterSecret, []byte(label), comm.CombineHash(ctx.HandshakeMessages, sha256.New), 12)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	finished := &Finished{VerifyData: verifyData}
	handshake := &Handshake{
		HandshakeType: HandshakeTypeFinished,
		Length:        uint32(len(verifyData)),
		Finished:      *finished,
		Payload:       finished.GetRaw(),
	}
	handshakeRaw := handshake.GetRaw()
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}
}

func NewAlert(level, description uint8) *Record {
	alert := &Alert{
		Level:       level,
		Description: description,
	}
	return &Record{
		ContentType: ContentTypeAlert,
		Version:     VersionTLS102,
		Length:      2,
		Alert:       *alert,
		Fragment:    alert.GetRaw(),
	}
}
