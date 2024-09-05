package mitm

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net/http"
	"net/http/httputil"
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
	ContentType      uint8     `json:"contentType"` //1 byte
	Version          uint16    `json:"version"`     //2 byte
	Length           uint16    `json:"length"`      //2 byte
	Fragment         []byte    `json:"fragment,omitempty"`
	Handshake        Handshake `json:"handshake,omitempty"`
	ChangeCipherSpec byte      `json:"changeCipherSpec,omitempty"`
	Alert            Alert     `json:"alert,omitempty"`
	ApplicationData  []byte
}

func NewBlockRecord(record *Record, ctx *Context) ([]byte, error) {
	seqNum := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNum, ctx.ServerSeqNum)

	// 生成MAC
	seqFragment := append(seqNum, record.GetRaw()...)
	//yaklog.Debugf("seqFragment Length : %d , seqFragment : %v", len(seqFragment), seqFragment)
	//todo
	mac := crypt.HmacHash(ctx.ServerMACKey, seqFragment, ctx.HashFunc)
	//yaklog.Debugf("mac Length : %d , mac : %v", len(mac), mac)

	ctx.ServerSeqNum++

	// 拼接Fragment和MAC
	plainFragment := append(record.Fragment, mac...)
	//yaklog.Debugf("plainFragment Length : %d , plainFragment : %v", len(plainFragment), plainFragment)

	// 拼接填充
	paddingLength := ctx.BlockLength - len(plainFragment)%ctx.BlockLength - 1
	//yaklog.Debugf("paddingLength : %v", paddingLength)
	padding := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
	//yaklog.Debugf("padding Length : %d , padding : %v", len(padding), padding)
	paddingFragment := append(plainFragment, append(padding, byte(paddingLength))...)
	//yaklog.Debugf("paddingFragment Length : %d , paddingFragment : %v", len(paddingFragment), paddingFragment)

	//todo
	//yaklog.Debugf("ServerIV length : %d , ServerIV : %v", len(ctx.ServerIV), ctx.ServerIV)
	//todo
	cipherFragment, err := crypt.AESCBCEncrypt(paddingFragment, ctx.ServerKey, ctx.ServerIV)
	if err != nil {
		return nil, err
	}
	//todo
	//yaklog.Debugf("ServerIV length : %d , ServerIV : %v", len(ctx.ServerIV), ctx.ServerIV)
	//yaklog.Debugf("cipherFragment Length : %d , cipherFragment : %v", len(cipherFragment), cipherFragment)

	// 拼接IV
	//todo
	fragment := append(ctx.ServerIV, cipherFragment...)
	//yaklog.Debugf("fragment Length : %d , fragment : %v", len(fragment), fragment)

	blockRecord := &Record{
		ContentType: record.ContentType,
		Version:     record.Version,
		Length:      uint16(len(fragment)),
		Fragment:    fragment,
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
			return append(record, r.ChangeCipherSpec)
		case ContentTypeAlert:
			return append(record, r.Alert.GetRaw()...)
		case ContentTypeApplicationData:
			return append(record, r.ApplicationData...)
		default:
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("not support Content Type : %v", r.ContentType)))
		}
	}
	return append(record, r.Fragment...)
}

func ParseBlockRecord(blockRecord []byte, ctx *Context) (*Record, error) {
	//yaklog.Debugf("blockRecord Length : %d , blockRecord : %v", len(blockRecord), blockRecord)

	// 获取对称解密的IV，获取需要解密的密文
	iv, cipherFragment := blockRecord[5:5+ctx.BlockLength], blockRecord[5+ctx.BlockLength:]
	//yaklog.Debugf("iv Length : %d , iv : %v", len(iv), iv)
	//yaklog.Debugf("cipherRecord Length : %d , cipherRecord : %v", len(cipherRecord), cipherRecord)

	// 解密密文
	paddingFragment, err := crypt.AESCBCDecrypt(cipherFragment, ctx.ClientKey, iv)
	if err != nil {
		return nil, err
	}
	//yaklog.Debugf("paddingFragment Length : %d , paddingFragment : %v", len(paddingFragment), paddingFragment)

	// 去除填充长度和填充数据
	plainFragment := paddingFragment[:len(paddingFragment)-int(paddingFragment[len(paddingFragment)-1])-1]
	//yaklog.Debugf("plainFragment Length : %d , plainFragment : %v", len(plainFragment), plainFragment)

	// 分离Fragment和MAC数据
	fragment, mac := plainFragment[:len(plainFragment)-ctx.MACLength], plainFragment[len(plainFragment)-ctx.MACLength:]
	//yaklog.Debugf("fragment Length : %d , fragment : %v", len(fragment), fragment)
	//yaklog.Debugf("mac Length : %d , mac : %v", len(mac), mac)

	// 生成明文Record
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(fragment)))
	plainRecord := append(blockRecord[:3], append(length, fragment...)...)
	//yaklog.Debugf("plainRecord Length : %d , plainRecord : %v", len(plainRecord), plainRecord)

	// 校验MAC防篡改
	if ctx.VerifyMAC {
		seqNum := make([]byte, 8)
		binary.BigEndian.PutUint64(seqNum, ctx.ClientSeqNum)
		tamplate := fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[plainRecord[0]]))
		if plainRecord[0] == ContentTypeHandshake {
			tamplate = fmt.Sprintf("%s [%s]", tamplate, comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[plainRecord[5]]))
		}

		// 服务端生成MAC
		verifyMAC := crypt.HmacHash(ctx.ClientMACKey, append(seqNum, plainRecord...), ctx.HashFunc)
		//yaklog.Debugf("verifyMAC Length : %d , verifyMAC : %v", len(verifyMAC), verifyMAC)

		// 校验MAC
		if hmac.Equal(mac, verifyMAC) {
			yaklog.Debugf("%s Verify MAC Successfully", tamplate)
		} else {
			return nil, fmt.Errorf("%s Verify MAC Failed", tamplate)
		}
	}

	ctx.ClientSeqNum++
	record, err := ParseRecord(plainRecord, ctx)
	if err != nil {
		return nil, err
	}

	//if record.Handshake.HandshakeType == HandshakeTypeFinished {
	//	ctx.Cache = cipherFragment
	//}

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
		if len(record.Fragment) != 1 {
			return nil, fmt.Errorf("Change Cipher Spec is invaild")
		}
		record.ChangeCipherSpec = record.Fragment[0]
	case ContentTypeAlert:
		alert, err := ParseAlert(record.Fragment, ctx)
		if err != nil {
			return nil, err
		}
		record.Alert = *alert
	case ContentTypeApplicationData:
		record.ApplicationData = record.Fragment
	default:
		yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("not support Content Type : %v", record.ContentType)))
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

func NewServerHello(ctx *Context) (*Record, error) {
	serverHello := &ServerHello{Version: ctx.Version}
	binary.BigEndian.PutUint32(serverHello.Random[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(serverHello.Random[4:]); err != nil {
		return nil, fmt.Errorf("create Random failed : %v", err)
	}
	serverHello.SessionIDLength = 32
	serverHello.SessionID = make([]byte, serverHello.SessionIDLength)
	if _, err := rand.Read(serverHello.SessionID); err != nil {
		return nil, fmt.Errorf("create SessionID failed : %v", err)
	}
	serverHello.CipherSuite = ctx.CipherSuite
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
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}, nil
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

func NewApplicationData(resp *http.Response, ctx *Context) (*Record, error) {
	fragment, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("dump Response failed : %v", err)
	}
	return &Record{
		ContentType:     ContentTypeApplicationData,
		Version:         ctx.Version,
		Length:          uint16(len(fragment)),
		Fragment:        fragment,
		ApplicationData: fragment,
	}, nil
}
