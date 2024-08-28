package protocol

import (
	"fmt"
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
	HandshakeType     uint8             `json:"handshakeType"` // 握手消息类型
	Length            uint32            `json:"length"`        // 有效载荷长度（3 字节）
	ClientHello       ClientHello       `json:"clientHello"`
	ServerHello       ServerHello       `json:"serverHello"`
	Certificate       Certificate       `json:"certificate"`
	ClientKeyExchange ClientKeyExchange `json:"clientKeyExchange"`
	Finished          Finished          `json:"finished"`
	Payload           []byte            `json:"payload"` // 有效载荷数据
}

func ParseHandshake(data []byte, args ...interface{}) (*Handshake, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("TLS Handshake is invalid")
	}
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	handshake := &Handshake{}
	if uint32(len(data)) != 4+length {
		if len(args) > 1 {
			finishedAlgorithm, ok := args[0].(uint16)
			if !ok {
				return nil, fmt.Errorf("can not get Finished Algorithm : %v", args[0])
			}
			finished, err := ParseFinished(data, finishedAlgorithm, args[1:]...)
			if err != nil {
				return nil, err
			}
			handshake.Finished = finished
		} else {
			return nil, fmt.Errorf("TLS Handshake Data is incomplete")
		}
	} else {
		handshake.HandshakeType = data[0]
		handshake.Length = length
		handshake.Payload = data[4 : 4+length]
		switch handshake.HandshakeType {
		case HandshakeTypeClientHello:
			clientHello, err := ParseClientHello(handshake.Payload)
			if err != nil {
				return nil, err
			}
			handshake.ClientHello = *clientHello
		case HandshakeTypeClientKeyExchange:
			keyExchangeAlgorithm, ok := args[0].(uint8)
			if !ok {
				return nil, fmt.Errorf("can not get Key Exchange Algorithm : %v", args[0])
			}
			clientKeyExchange, err := ParseClientKeyExchange(handshake.Payload, keyExchangeAlgorithm)
			if err != nil {
				return nil, err
			}
			handshake.ClientKeyExchange = clientKeyExchange
		}
	}
	return handshake, nil
}

func (h *Handshake) GetRaw() []byte {
	length := []byte{byte(h.Length >> 16), byte(h.Length >> 8), byte(h.Length)}
	handshake := append([]byte{h.HandshakeType}, length...)
	if h.Length > 0 {
		switch h.HandshakeType {
		case HandshakeTypeServerHello:
			if &h.ServerHello != nil {
				return append(handshake, h.ServerHello.GetRaw()...)
			}
			fallthrough
		case HandshakeTypeCertificate:
			if &h.Certificate != nil {
				return append(handshake, h.Certificate.GetRaw()...)
			}
			fallthrough
		default:
			return append(handshake, h.Payload...)
		}
	}
	//yaklog.Debugf("Payload : %s", comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%v", handshake)))
	return handshake
}
