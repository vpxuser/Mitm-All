package mitm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/color"
	"socks2https/pkg/crypt"
)

const (
	KeyExchangeRSA uint8 = iota
	KeyExchangeDHE
	KeyExchangeECDHE
	KeyExchangePSK
)

// ClientKeyExchange 定义 ClientKeyExchange 的通用接口
type ClientKeyExchange interface {
	Parse(data []byte, ctx *Context) error
}

// RSAClientKeyExchange 表示 RSA 密钥交换的 ClientKeyExchange
type RSAClientKeyExchange struct {
	EncrypedPreMasterLength uint16
	EncrypedPreMasterSecret []byte
}

// Parse 实现 ClientKeyExchange 接口的 Parse 方法
func (r *RSAClientKeyExchange) Parse(data []byte, ctx *Context) error {
	if len(data) < 2 {
		return fmt.Errorf("RSA ClientKeyExchange is invalid")
	}
	r.EncrypedPreMasterLength = binary.BigEndian.Uint16(data[0:2])
	r.EncrypedPreMasterSecret = data[2 : 2+r.EncrypedPreMasterLength]
	return nil
}

// ParseClientKeyExchange 解析 ClientKeyExchange 消息
func ParseClientKeyExchange(data []byte, ctx *Context) (ClientKeyExchange, error) {
	var clientKeyExchange ClientKeyExchange
	switch ctx.KeyExchangeAlgorithm {
	case KeyExchangeRSA:
		clientKeyExchange = &RSAClientKeyExchange{}
	default:
		return nil, fmt.Errorf("not supported Client Key Exchange Algorithm : %d", ctx.KeyExchangeAlgorithm)
	}
	if err := clientKeyExchange.Parse(data, ctx); err != nil {
		return nil, err
	}
	return clientKeyExchange, nil
}

var ReadClientKeyExchange = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Handshake"), color.SetColor(color.RED_COLOR_TYPE, "Client Key Exchange"))

	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeClientKeyExchange, ctx)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}

	// 存储握手记录，用于后续Finished的Verify_Data计算
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)

	// RSA解密Pre_Master_Secret
	clientKeyExchange := record.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	preMasterSecret, err := crypt.DecryptRSAPKCS(ctx.KeyDER, clientKeyExchange.EncrypedPreMasterSecret)
	if err != nil {
		return err
	}
	ctx.PreMasterSecret = preMasterSecret

	yaklog.Infof("%s PreMasterSecret : %x", tamplate, preMasterSecret)

	// 使用PRF算法计算出Master_Secret
	version := binary.BigEndian.Uint16(preMasterSecret[:2])
	masterSecret := PRF[version](preMasterSecret, []byte(LabelMasterSecret), append(ctx.ClientRandom[:], ctx.ServerRandom[:]...), len(preMasterSecret))
	ctx.MasterSecret = masterSecret

	// 使用PRF算法和Master_Secret计算Session_Key（会话密钥）
	ctx.SessionKey = PRF[version](masterSecret, []byte(LabelKeyExpansion), append(ctx.ServerRandom[:], ctx.ClientRandom[:]...), 2*(ctx.MACLength+2*ctx.BlockLength))

	// 从会话密钥截取后续加解密消息类型使用的HMAC签名密钥
	ctx.ClientMACKey, ctx.ServerMACKey = ctx.SessionKey[:ctx.MACLength], ctx.SessionKey[ctx.MACLength:2*ctx.MACLength]

	// 从会话密钥截取后续加解密消息类型使用的对称密钥
	ctx.ClientKey, ctx.ServerKey = ctx.SessionKey[2*ctx.MACLength:2*ctx.MACLength+ctx.BlockLength], ctx.SessionKey[2*ctx.MACLength+ctx.BlockLength:2*(ctx.MACLength+ctx.BlockLength)]

	// 从会话密钥截取后续加解密消息类型使用的对称向量，向量一般不需要生成，下面代码可以不要
	ctx.ClientIV, ctx.ServerIV = ctx.SessionKey[2*(ctx.MACLength+ctx.BlockLength):2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength], ctx.SessionKey[2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength:]

	return nil
})
