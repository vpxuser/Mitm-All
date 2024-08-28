package socks

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
	"socks2https/pkg/crypt"
)

const (
	// TLS 1.2 Cipher Suites
	TLS_RSA_WITH_AES_128_CBC_SHA          uint16 = 0x002F
	TLS_RSA_WITH_AES_256_CBC_SHA          uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256       uint16 = 0x003C
	TLS_RSA_WITH_AES_256_CBC_SHA256       uint16 = 0x003D
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    uint16 = 0xC013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    uint16 = 0xC014
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 uint16 = 0xC027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 uint16 = 0xC028

	// TLS 1.3 Cipher Suites
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	TLS_AES_128_CCM_SHA256       uint16 = 0x1304
	TLS_AES_128_CCM_8_SHA256     uint16 = 0x1305

	// Other Common Cipher Suites
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xC02B
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xC02C
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xC02F
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xC030
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xCCA9
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xCCA8
)

// Finished 定义一个接口，用于不同加密算法的 Finished 消息解析
type Finished interface {
	Parse(data []byte, ctx *Context) error
}

type AESCBCFinished []byte

// Parse 实现 Finished 接口的 Parse 方法，用于解析 AES 128 CBC 的 Finished 消息
func (a *AESCBCFinished) Parse(data []byte, ctx *Context) error {
	copy(*a, data)
	//todo
	clientKeyExchange := ctx.ClientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	verifyData, err := crypt.DecryptAESCBC(data, clientKeyExchange.ServerKey, clientKeyExchange.ServerIV)
	if err != nil {
		return err
	}
	yaklog.Debugf(comm.SetColor(comm.RED_BG_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	return nil
}

// ParseFinished 根据传入的数据解析 Finished 消息
func ParseFinished(data []byte, ctx *Context) (Finished, error) {
	var finished Finished
	switch ctx.CipherSuite {
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		finished = &AESCBCFinished{}
	default:
		return nil, fmt.Errorf("unsupported Cipher Suite : %d", ctx.CipherSuite)
	}
	if err := finished.Parse(data, ctx); err != nil {
		return nil, err
	}
	return finished, nil
}
