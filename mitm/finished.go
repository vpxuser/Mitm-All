package mitm

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"net"
	"socks2https/pkg/color"
	"socks2https/setting"
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

func VerifyPRF(version uint16, secret, label []byte, handshakeMessages [][]byte, outputLength int) []byte {
	var hashFunc hash.Hash
	switch version {
	case tls.VersionTLS12:
		hashFunc = sha256.New()
	default:
		return nil
	}
	for _, message := range handshakeMessages {
		hashFunc.Write(message)
	}
	return PRF[version](secret, label, hashFunc.Sum(nil), outputLength)
}

func NewFinished(ctx *Context) *Record {
	//yaklog.Debugf("Handshake Messages Length : %d", len(ctx.HandshakeMessages))
	//for i, h := range ctx.HandshakeMessages {
	//	yaklog.Debugf("Handshake Messages %d : %v", i, h)
	//}
	verifyData := VerifyPRF(ctx.Version, ctx.MasterSecret, []byte(LabelServerFinished), ctx.HandshakeMessages, 12)
	//yaklog.Debugf(color.SetColor(color.RED_COLOR_TYPE, fmt.Sprintf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)))
	//yaklog.Debugf("Verify Data Length : %d , Verify Data : %v", len(verifyData), verifyData)
	handshake := &Handshake{
		HandshakeType: HandshakeTypeFinished,
		Length:        uint32(len(verifyData)),
		Payload:       verifyData,
		Finished:      verifyData,
	}
	handshakeRaw := handshake.GetRaw()
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Fragment:    handshakeRaw,
		Handshake:   *handshake,
	}
}

var ReadFinished = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Handshake"), color.SetColor(color.RED_COLOR_TYPE, "Finished"))

	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeFinished, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)

	if setting.Config.TLS.VerifyFinished {
		verifyData := VerifyPRF(ctx.Version, ctx.MasterSecret, []byte(LabelClientFinished), ctx.HandshakeMessages, 12)
		if hmac.Equal(verifyData, record.Handshake.Payload) {
			return fmt.Errorf("%s Verify Client Finished Failed", tamplate)
		}
		yaklog.Infof("%s Verify Client Finished Successfully", tamplate)
	} else {
		yaklog.Infof("%s Not Need to Verify Finished", tamplate)
	}
	return nil
})

var WriteFinished = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Handshake"), color.SetColor(color.RED_COLOR_TYPE, "Finished"))
	blockRecord, err := NewBlockRecord(NewFinished(ctx), ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	if _, err := conn.Write(blockRecord); err != nil {
		return fmt.Errorf("%s Write Server Finished Failed : %v", tamplate, err)
	}

	yaklog.Infof("%s Write Server Finished Successfully", tamplate)
	return nil
})
