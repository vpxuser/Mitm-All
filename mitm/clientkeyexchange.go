package mitm

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
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Encrypted PreMasterSecret Length : %d , Encrypted PreMasterSecret : %v", len(r.EncrypedPreMasterSecret), r.EncrypedPreMasterSecret)))

	//preMasterSecret, err := crypt.DecryptRSAPKCS(ctx.KeyDER, r.EncrypedPreMasterSecret)
	//if err != nil {
	//	return fmt.Errorf("RSA Decrypt PreMasterSecret failed : %v", err)
	//}
	//ctx.PreMasterSecret = preMasterSecret
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("PreMasterSecret Length : %d , PreMasterSecret : %v", len(preMasterSecret), preMasterSecret)))

	//yaklog.Debugf("Client Random : %v", ctx.ClientHello.Handshake.ClientHello.Random)
	//yaklog.Debugf("Server Random : %v", ctx.ServerHello.Handshake.ServerHello.Random)
	//var prf crypt.PRF
	//switch binary.BigEndian.Uint16(preMasterSecret[:2]) {
	//case VersionTLS102:
	//	prf = crypt.TLS102PRF
	//default:
	//	return fmt.Errorf("not support RSA ClientKeyExchange")
	//}
	//masterSecret := prf(preMasterSecret, []byte(crypt.LabelMasterSecret), append(ctx.ClientRandom[:], ctx.ServerRandom[:]...), len(preMasterSecret))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MasterSecret Length : %d , MasterSecret : %v", len(masterSecret), masterSecret)))
	//ctx.MasterSecret = masterSecret

	//ctx.KeyBlock = prf(masterSecret, []byte(crypt.LabelKeyExpansion), append(ctx.ServerRandom[:], ctx.ClientRandom[:]...), 2*(ctx.MACLength+2*ctx.BlockLength))
	////yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Key Expansion Length : %d , Key Expansion : %v", len(ctx.KeyBlock), ctx.KeyBlock)))
	//
	//ctx.ClientMACKey, ctx.ServerMACKey = ctx.KeyBlock[:ctx.MACLength], ctx.KeyBlock[ctx.MACLength:2*ctx.MACLength]
	//ctx.ClientKey, ctx.ServerKey = ctx.KeyBlock[2*ctx.MACLength:2*ctx.MACLength+ctx.BlockLength], ctx.KeyBlock[2*ctx.MACLength+ctx.BlockLength:2*(ctx.MACLength+ctx.BlockLength)]
	//ctx.ClientIV, ctx.ServerIV = ctx.KeyBlock[2*(ctx.MACLength+ctx.BlockLength):2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength], ctx.KeyBlock[2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength:]
	////yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Mac Keys Length : %d , Client Mac Keys : %v", len(ctx.ClientMACKey), ctx.ClientMACKey)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Mac Keys Length : %d , Server Mac Keys : %v", len(ctx.ServerMACKey), ctx.ServerMACKey)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Key Length : %d , Client Key : %v", len(ctx.ClientKey), ctx.ClientKey)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Key Length : %d , Server Key : %v", len(ctx.ServerKey), ctx.ServerKey)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client IV Length : %d , Client IV : %v", len(ctx.ClientIV), ctx.ClientIV)))
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server IV Length : %d , Server IV : %v", len(ctx.ServerIV), ctx.ServerIV)))
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
