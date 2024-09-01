package mitm

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
)

// TLS 握手消息类型
const (
	HandshakeTypeHelloRequest       uint8 = 0x00 // 请求客户端发起Hello消息
	HandshakeTypeClientHello        uint8 = 0x01 // 客户端发起握手请求
	HandshakeTypeServerHello        uint8 = 0x02 // 服务器响应客户端Hello消息
	HandshakeTypeHelloRetryRequest  uint8 = 0x03 // 服务器请求客户端重新发起Hello消息
	HandshakeTypeNewSessionTicket   uint8 = 0x04 // 会话票据
	HandshakeTypeEndOfEarlyData     uint8 = 0x05 // 结束早期数据交换
	HandshakeTypeCertificate        uint8 = 0x0B // 服务器或客户端发送的证书
	HandshakeTypeServerKeyExchange  uint8 = 0x0C // 服务器密钥交换
	HandshakeTypeCertificateRequest uint8 = 0x0D // 服务器请求客户端证书
	HandshakeTypeServerHelloDone    uint8 = 0x0E // 服务器完成Hello阶段
	HandshakeTypeCertificateVerify  uint8 = 0x0F // 客户端或服务器验证证书
	HandshakeTypeClientKeyExchange  uint8 = 0x10 // 客户端密钥交换
	HandshakeTypeFinished           uint8 = 0x14 // 握手完成消息
)

var HandshakeType = map[byte]string{
	HandshakeTypeHelloRequest:       "Hello Request",
	HandshakeTypeClientHello:        "Client Hello",
	HandshakeTypeServerHello:        "Server Hello",
	HandshakeTypeHelloRetryRequest:  "Hello Retry Request",
	HandshakeTypeNewSessionTicket:   "New Session Ticket",
	HandshakeTypeEndOfEarlyData:     "End of Early Data",
	HandshakeTypeCertificate:        "Certificate",
	HandshakeTypeServerKeyExchange:  "Server Key Exchange",
	HandshakeTypeCertificateRequest: "Certificate Request",
	HandshakeTypeServerHelloDone:    "Server Hello Done",
	HandshakeTypeCertificateVerify:  "Certificate Verify",
	HandshakeTypeClientKeyExchange:  "Client Key Exchange",
	HandshakeTypeFinished:           "Finished",
}

type Handshake struct {
	HandshakeType     uint8             `json:"handshakeType"`     // 握手消息类型
	Length            uint32            `json:"length"`            // 有效载荷长度（3 字节）
	Payload           []byte            `json:"payload,omitempty"` // 有效载荷数据
	ClientHello       ClientHello       `json:"clientHello,omitempty"`
	ServerHello       ServerHello       `json:"serverHello,omitempty"`
	Certificate       Certificate       `json:"certificate,omitempty"`
	ClientKeyExchange ClientKeyExchange `json:"clientKeyExchange,omitempty"`
	Finished          Finished          `json:"finished,omitempty"`
}

func ParseHandshake(data []byte, ctx *Context) (*Handshake, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("TLS Handshake is invaild")
	}
	handshake := &Handshake{
		HandshakeType: data[0],
		Length:        uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
	}
	if len(data) != 4+int(handshake.Length) {
		return nil, fmt.Errorf("TLS Handshake Payload is incomplete")
	}
	handshake.Payload = data[4 : 4+handshake.Length]
	switch handshake.HandshakeType {
	case HandshakeTypeClientHello:
		clientHello, err := ParseClientHello(handshake.Payload)
		if err != nil {
			return nil, err
		}
		handshake.ClientHello = *clientHello
	case HandshakeTypeClientKeyExchange:
		clientKeyExchange, err := ParseClientKeyExchange(handshake.Payload, ctx)
		if err != nil {
			return nil, err
		}
		handshake.ClientKeyExchange = clientKeyExchange
	case HandshakeTypeFinished:
		finished, err := ParseFinished(handshake.Payload, ctx)
		if err != nil {
			return nil, err
		}
		handshake.Finished = *finished
	}
	return handshake, nil
}

func (h *Handshake) GetRaw() []byte {
	length := []byte{byte(h.Length >> 16), byte(h.Length >> 8), byte(h.Length)}
	handshake := append([]byte{h.HandshakeType}, length...)
	if h.Payload == nil {
		switch h.HandshakeType {
		case HandshakeTypeServerHello:
			return append(handshake, h.ServerHello.GetRaw()...)
		case HandshakeTypeCertificate:
			return append(handshake, h.Certificate.GetRaw()...)
		case HandshakeTypeFinished:
			return append(handshake, h.Finished.GetRaw()...)
		default:
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("not support Handshake Type : %d", h.HandshakeType)))
		}
	}
	return append(handshake, h.Payload...)
}
