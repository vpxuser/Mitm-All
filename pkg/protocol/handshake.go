package protocol

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
)

// TLS 握手消息类型
const (
	MessageTypeHelloRequest       uint8 = 0x00 // 请求客户端发起Hello消息
	MessageTypeClientHello        uint8 = 0x01 // 客户端发起握手请求
	MessageTypeServerHello        uint8 = 0x02 // 服务器响应客户端Hello消息
	MessageTypeHelloRetryRequest  uint8 = 0x03 // 服务器请求客户端重新发起Hello消息
	MessageTypeNewSessionTicket   uint8 = 0x04 // 会话票据
	MessageTypeEndOfEarlyData     uint8 = 0x05 // 结束早期数据交换
	MessageTypeCertificate        uint8 = 0x0B // 服务器或客户端发送的证书
	MessageTypeServerKeyExchange  uint8 = 0x0C // 服务器密钥交换
	MessageTypeCertificateRequest uint8 = 0x0D // 服务器请求客户端证书
	MessageTypeServerHelloDone    uint8 = 0x0E // 服务器完成Hello阶段
	MessageTypeCertificateVerify  uint8 = 0x0F // 客户端或服务器验证证书
	MessageTypeClientKeyExchange  uint8 = 0x10 // 客户端密钥交换
	MessageTypeFinished           uint8 = 0x14 // 握手完成消息
)

var MessageType = map[byte]string{
	MessageTypeHelloRequest:       "Hello Request",
	MessageTypeClientHello:        "Client Hello",
	MessageTypeServerHello:        "Server Hello",
	MessageTypeHelloRetryRequest:  "Hello Retry Request",
	MessageTypeNewSessionTicket:   "New Session Ticket",
	MessageTypeEndOfEarlyData:     "End of Early Data",
	MessageTypeCertificate:        "Certificate",
	MessageTypeServerKeyExchange:  "Server Key Exchange",
	MessageTypeCertificateRequest: "Certificate Request",
	MessageTypeServerHelloDone:    "Server Hello Done",
	MessageTypeCertificateVerify:  "Certificate Verify",
	MessageTypeClientKeyExchange:  "Client Key Exchange",
	MessageTypeFinished:           "Finished Message",
}

type TLSHandshakeMessage struct {
	MessageType uint8       `json:"messageType"` // 握手消息类型
	Length      uint32      `json:"length"`      // 有效载荷长度（3 字节）
	Data        []byte      `json:"data"`        // 有效载荷数据
	ClientHello ClientHello `json:"clientHello"`
	ServerHello ServerHello `json:"serverHello"`
	Certificate Certificate `json:"certificate"`
}

func ParseHandshakeMessage(data []byte) (*TLSHandshakeMessage, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("TLS Handshake is invalid")
	}
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data)) < 4+length {
		return nil, fmt.Errorf("TLS Handshake Data is incomplete")
	}
	tlsHandshakeMessage := &TLSHandshakeMessage{
		MessageType: data[0],
		Length:      length,
		Data:        data[4 : 4+length],
	}
	switch tlsHandshakeMessage.MessageType {
	case MessageTypeClientHello:
		clientHello, err := ParseClientHello(tlsHandshakeMessage.Data)
		if err != nil {
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("parse Client Hello failed : %v", err)))
			break
		}
		tlsHandshakeMessage.ClientHello = *clientHello
	}
	return tlsHandshakeMessage, nil
}

func (h *TLSHandshakeMessage) GetRaw() []byte {
	length := []byte{byte(h.Length & 0xff), byte((h.Length >> 8) & 0xff), byte((h.Length >> 16) & 0xff)}
	header := append([]byte{h.MessageType}, length...)
	switch true {
	case &h.ServerHello != nil:
		return append(header, h.ServerHello.GetRaw()...)
	case &h.Certificate != nil:
		return append(header, h.Certificate.GetRaw()...)
	default:
		return append(header, h.Data...)
	}
}
