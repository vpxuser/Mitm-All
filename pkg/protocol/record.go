package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
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

type TLSRecordLayer struct {
	ContentType         uint8               `json:"contentType"` //1 byte
	Version             uint16              `json:"version"`     //2 byte
	Length              uint16              `json:"length"`      //2 byte
	Fragment            []byte              `json:"fragment"`
	TLSHandshakeMessage TLSHandshakeMessage `json:"tlsHandshakeMessage"`
}

func ParseTLSRecordLayer(data []byte) (*TLSRecordLayer, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("TLS Record is invalid")
	}
	reader := bytes.NewReader(data)
	record := &TLSRecordLayer{}
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
		handshakeMessage, err := ParseHandshakeMessage(record.Fragment)
		if err != nil {
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("parse Handshake Message failed: %v", err)))
			break
		}
		record.TLSHandshakeMessage = *handshakeMessage
	}
	return record, nil
}

func (r *TLSRecordLayer) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, r.Version)
	header := append([]byte{r.ContentType}, version...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, r.Length)
	header = append(header, length...)
	switch true {
	case &r.TLSHandshakeMessage != nil:
		return append(header, r.TLSHandshakeMessage.GetRaw()...)
	default:
		return append(header, r.Fragment...)
	}
}

func (r *TLSRecordLayer) GetSNI() string {
	for _, extension := range r.TLSHandshakeMessage.ClientHello.Extensions {
		if extension.Type == ExtensionTypeServerName {
			serverNameList := extension.ServerNameIndication.ServerNameList
			if len(serverNameList) > 0 {
				return serverNameList[0].HostName
			}
			break
		}
	}
	return ""
}

func GenrateServerHelloRaw(clientHello *ClientHello) ([]byte, error) {
	//clientHello, err := ParseClientHello(clientHelloRaw[9:])
	//if err != nil {
	//	return nil, fmt.Errorf("parse ClientHello failed : %v", err)
	//}
	serverHello, err := clientHello.GenrateServerHello()
	if err != nil {
		return nil, fmt.Errorf("genrate ServerHello failed : %v", err)
	}
	serverHelloJSON, _ := json.MarshalIndent(serverHello, "", "  ")
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Hello :\n%s", serverHelloJSON)))
	serverHelloRaw := serverHello.GetRaw()
	handShake := &TLSHandshakeMessage{
		MessageType: MessageTypeServerHello,
		Length:      uint32(len(serverHelloRaw)),
		Data:        serverHelloRaw,
	}
	handShakeRaw := handShake.GetRaw()
	record := &TLSRecordLayer{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Length:      uint16(len(handShakeRaw)),
		Fragment:    handShakeRaw,
	}
	return record.GetRaw(), nil
}

func NewCertificate(path, domain string) (*TLSRecordLayer, error) {
	certDER, _, err := cert.GetCertificateAndKey(path, domain)
	if err != nil {
		return nil, err
	}
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
	handShake := &TLSHandshakeMessage{
		MessageType: MessageTypeServerHello,
		Length:      uint32(len(certificateRaw)),
		Data:        certificateRaw,
	}
	handShakeRaw := handShake.GetRaw()
	record := &TLSRecordLayer{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Length:      uint16(len(handShakeRaw)),
		Fragment:    handShakeRaw,
	}
	return record, nil
}
