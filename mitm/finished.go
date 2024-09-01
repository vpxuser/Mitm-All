package mitm

import (
	"crypto/hmac"
	"crypto/sha1"
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
	clientKeyExchange := ctx.ClientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	iv, chiperData := data[:16], data[16:]
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("IV Length : %d , IV Data : %v", len(iv), iv)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Chiper Data Length : %d , Chiper Data Data : %v", len(chiperData), chiperData)))
	plainData, err := crypt.AESCBCDecrypt(chiperData, clientKeyExchange.ClientKey, iv)
	if err != nil {
		return nil, err
	}
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Plain Length : %d , Plain Data : %v", len(plainData), plainData)))
	//ctx.HandshakeMessages = append(ctx.HandshakeMessages, plainData[:16])
	//handshakeHeader := plainData[:4]
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Handshake Header Length : %d , Handshake Header Data : %v", len(handshakeHeader), handshakeHeader)))
	verifyData, MAC := plainData[4:16], plainData[16:36]
	finished := &Finished{VerifyData: verifyData}
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	expectVerifyData := PRF(clientKeyExchange.MasterSecret, []byte(crypt.LabelClientFinished), comm.CombineHash(ctx.HandshakeMessages, sha256.New), len(verifyData))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Expect Verify Data Length : %d , Expect Verify Data : %v", len(expectVerifyData), expectVerifyData)))
	if hmac.Equal(verifyData, expectVerifyData) {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Finished Verify Success")))
	} else {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Finished Verify Failed")))
	}
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MAC Length : %d , MAC Data : %v", len(MAC), MAC)))
	//A := append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0x16, 0x03, 0x03, 0x00, 0x10}, plainData[:16]...)
	newFinished := NewFinished(crypt.LabelClientFinished, ctx)
	//yaklog.Debugf("A : %v", A)
	//expectMAC := crypt.HmacHash(clientKeyExchange.ClientMacKey, newFinished.GetRaw(), sha1.New)
	expectMAC := crypt.MAC(clientKeyExchange.ClientMacKey, ctx.ClientSeqNum, newFinished.GetRaw(), sha1.New)
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Expect MAC Length : %d , Expect MAC Data : %v", len(expectMAC), expectMAC)))
	if hmac.Equal(MAC, expectMAC) {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MAC Verify Success")))
	} else {
		yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MAC Verify Failed")))
	}
	return finished, nil
}

func (f *Finished) GetRaw() []byte {
	return *f
}
