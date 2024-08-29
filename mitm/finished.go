package mitm

import (
	"crypto/hmac"
	"crypto/sha256"
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

type Finished []byte

// ParseFinished 根据传入的数据解析 Finished 消息
func ParseFinished(data []byte, ctx *Context) (*Finished, error) {
	finished := &Finished{}
	copy(*finished, data)
	clientKeyExchange := ctx.ClientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	//finishedKey := PRF(clientKeyExchange.MasterSecret, []byte(LabelKeyExpansion), nil, 12)
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Finished Key Length : %d , Finished Key Data : %v", len(finishedKey), finishedKey)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(data), data)))
	//expectData := HmacHash(finishedKey, comm.CombineHash(ctx.HandshakeRawList, sha256.New), sha256.New)
	expectData := PRF(clientKeyExchange.MasterSecret, []byte(LabelClientFinished), comm.CombineHash(ctx.HandshakeRawList, sha256.New), 12)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Expect Data Length : %d , Expect Data : %v", len(expectData), expectData)))
	verifyData, err := crypt.DecryptAESCBC(data, clientKeyExchange.ClientKey, clientKeyExchange.ClientIV)
	if err != nil {
		return nil, err
	}
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	if hmac.Equal(verifyData, expectData) {
		//if hmac.Equal(data, expectData) {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Client Finished Success")))
	} else {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Client Finished Failed")))
	}
	return finished, nil
}
