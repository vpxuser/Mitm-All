package protocol

import (
	"encoding/binary"
	"fmt"
)

const (
	KeyExchangeRSA uint8 = iota
	KeyExchangeDHE
	KeyExchangeECDHE
	KeyExchangePSK
)

// ClientKeyExchange 定义 ClientKeyExchange 的通用接口
type ClientKeyExchange interface {
	Parse(data []byte) error
}

// ClientKeyExchangeRSA 表示 RSA 密钥交换的 ClientKeyExchange
type ClientKeyExchangeRSA struct {
	EncryptedPreMasterLength uint16
	EncryptedPreMasterSecret []byte
}

// Parse 实现 ClientKeyExchange 接口的 Parse 方法
func (c *ClientKeyExchangeRSA) Parse(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("RSA ClientKeyExchange is invalid")
	}
	c.EncryptedPreMasterLength = binary.BigEndian.Uint16(data[0:2])
	c.EncryptedPreMasterSecret = data[2 : 2+c.EncryptedPreMasterLength] // 修正偏移量
	return nil
}

// ParseClientKeyExchange 解析 ClientKeyExchange 消息
func ParseClientKeyExchange(data []byte, keyExchangeAlgorithm uint8) (ClientKeyExchange, error) {
	var clientKeyExchange ClientKeyExchange
	switch keyExchangeAlgorithm {
	case KeyExchangeRSA:
		clientKeyExchange = &ClientKeyExchangeRSA{}
	default:
		return nil, fmt.Errorf("unsupported Client Key Exchange Algorithm : %d", keyExchangeAlgorithm)
	}
	if err := clientKeyExchange.Parse(data); err != nil {
		return nil, err
	}
	return clientKeyExchange, nil
}
