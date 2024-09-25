package tlshandler

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/crypt"
	"socks2https/pkg/tlsutils"
)

var ReadClientKeyExchange = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Client Key Exchange"))

	record, err := tlsutils.FilterRecord(reader, tlsutils.ContentTypeHandshake, tlsutils.HandshakeTypeClientKeyExchange, ctx)
	if err != nil {
		//yaklog.Errorf("%s %v", tamplate, err)
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return err
	}

	// 存储握手记录，用于后续Finished的Verify_Data计算
	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, record.Fragment)

	// RSA解密Pre_Master_Secret
	clientKeyExchange := record.Handshake.ClientKeyExchange.(*tlsutils.RSAClientKeyExchange)
	preMasterSecret, err := crypt.DecryptRSAPKCS(ctx.TLSContext.KeyDER, clientKeyExchange.EncrypedPreMasterSecret)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	yaklog.Infof("%s PreMasterSecret : %x", tamplate, preMasterSecret)

	// 使用PRF算法计算出Master_Secret
	version := binary.BigEndian.Uint16(preMasterSecret[:2])
	masterSecret := crypt.PRF[version](preMasterSecret, []byte(crypt.LabelMasterSecret), append(ctx.TLSContext.ClientRandom[:], ctx.TLSContext.ServerRandom[:]...), len(preMasterSecret))
	ctx.TLSContext.MasterSecret = masterSecret

	// 使用PRF算法和Master_Secret计算Session_Key（会话密钥）
	sessionKey := crypt.PRF[version](masterSecret, []byte(crypt.LabelKeyExpansion), append(ctx.TLSContext.ServerRandom[:], ctx.TLSContext.ClientRandom[:]...), 2*(ctx.TLSContext.MACLength+2*ctx.TLSContext.BlockLength))

	// 从会话密钥截取后续加解密消息类型使用的HMAC签名密钥
	ctx.TLSContext.ClientMACKey, ctx.TLSContext.ServerMACKey = sessionKey[:ctx.TLSContext.MACLength], sessionKey[ctx.TLSContext.MACLength:2*ctx.TLSContext.MACLength]

	// 从会话密钥截取后续加解密消息类型使用的对称密钥
	ctx.TLSContext.ClientKey, ctx.TLSContext.ServerKey = sessionKey[2*ctx.TLSContext.MACLength:2*ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength], sessionKey[2*ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength:2*(ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength)]

	// 从会话密钥截取后续加解密消息类型使用的对称向量，向量一般不需要生成，下面代码可以不要
	ctx.TLSContext.ClientIV, ctx.TLSContext.ServerIV = sessionKey[2*(ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength):2*(ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength)+ctx.TLSContext.BlockLength], sessionKey[2*(ctx.TLSContext.MACLength+ctx.TLSContext.BlockLength)+ctx.TLSContext.BlockLength:]

	return nil
})
