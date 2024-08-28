package socks

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"socks2https/pkg/comm"
	"socks2https/pkg/crypt"
)

const (
	KeyExchangeRSA uint8 = iota
	KeyExchangeDHE
	KeyExchangeECDHE
	KeyExchangePSK
)

const (
	LabelMasterSecret             = "master secret"
	LabelKeyExpansion             = "key expansion"
	LabelClientFinished           = "client finished"
	LabelServerFinished           = "server finished"
	LabelClientEAPMasterSecret    = "client EAP master secret"
	LabelServerEAPMasterSecret    = "server EAP master secret"
	LabelExtendedMasterSecret     = "extended master secret"
	LabelResumptionMasterSecret   = "resumption master secret"
	LabelExporterMasterSecret     = "exporter master secret"
	LabelEarlyTrafficSecret       = "early traffic secret"
	LabelHandshakeTrafficSecret   = "handshake traffic secret"
	LabelApplicationTrafficSecret = "application traffic secret"
	LabelExporter                 = "EXPORTER"
	LabelFinished                 = "finished"
	LabelBinding                  = "binding"
	LabelSessionTicket            = "session ticket"
)

// ClientKeyExchange 定义 ClientKeyExchange 的通用接口
type ClientKeyExchange interface {
	Parse(data []byte, ctx *Context) error
}

// RSAClientKeyExchange 表示 RSA 密钥交换的 ClientKeyExchange
type RSAClientKeyExchange struct {
	EncrypedPreMasterLength uint16
	EncrypedPreMasterSecret []byte
	PreMasterSecret         []byte
	MasterSecret            []byte
	KeyExpansion            []byte
	ClientKey               []byte
	ServerKey               []byte
	ClientIV                []byte
	ServerIV                []byte
	MacKey                  []byte
	ClientMacKey            []byte
	ServerMacKey            []byte
}

// PRF 使用 HMAC-SHA* 实现 TLS PRF
func PRF(secret, seed []byte, label string, hashFunc func() hash.Hash, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	hmacFunc := hmac.New(hashFunc, secret)
	hmacFunc.Write(labelAndSeed)
	result := hmacFunc.Sum(nil)
	for len(result) < length {
		hmacFunc.Reset()
		hmacFunc.Write(result[len(result)-hmacFunc.Size():])
		hmacFunc.Write(labelAndSeed)
		result = append(result, hmacFunc.Sum(nil)...)
	}
	return result[:length]
}

// Parse 实现 ClientKeyExchange 接口的 Parse 方法
func (r *RSAClientKeyExchange) Parse(data []byte, ctx *Context) error {
	if len(data) < 2 {
		return fmt.Errorf("RSA ClientKeyExchange is invalid")
	}
	r.EncrypedPreMasterLength = binary.BigEndian.Uint16(data[0:2])
	r.EncrypedPreMasterSecret = data[2 : 2+r.EncrypedPreMasterLength]
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Encrypted PreMasterSecret Length : %d , Encrypted PreMasterSecret : %v", len(r.EncrypedPreMasterSecret), r.EncrypedPreMasterSecret)))

	preMasterSecret, err := crypt.DecryptPKCS1RSA(ctx.KeyDER, r.EncrypedPreMasterSecret)
	if err != nil {
		return err
	}
	r.PreMasterSecret = preMasterSecret
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("PreMasterSecret Length : %d , PreMasterSecret : %v", len(preMasterSecret), preMasterSecret)))

	seed := append(ctx.ClientHello.Handshake.ClientHello.Random[:], ctx.ServerHello.Handshake.ServerHello.Random[:]...)
	masterSecret := PRF(preMasterSecret, seed, LabelMasterSecret, ctx.HashFunc, 48)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MasterSecret Length : %d , MasterSecret : %v", len(masterSecret), masterSecret)))
	r.MasterSecret = masterSecret

	keyLength, ivLength, macKeyLength := 16, 16, 20 // AES-128 密钥长度

	r.KeyExpansion = PRF(masterSecret, seed, LabelKeyExpansion, ctx.HashFunc, 2*(keyLength+ivLength))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Key Expansion Length : %d , Key Expansion : %v", len(r.KeyExpansion), r.KeyExpansion)))

	r.ClientKey, r.ServerKey, r.ClientIV, r.ServerIV = r.KeyExpansion[:keyLength], r.KeyExpansion[keyLength:2*keyLength], r.KeyExpansion[2*keyLength:2*keyLength+ivLength], r.KeyExpansion[2*keyLength+ivLength:]
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Key Length : %d , Client Key : %v", len(r.ClientKey), r.ClientKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Key Length : %d , Server Key : %v", len(r.ServerKey), r.ServerKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client IV Length : %d , Client IV : %v", len(r.ClientIV), r.ClientIV)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server IV Length : %d , Server IV : %v", len(r.ServerIV), r.ServerIV)))

	r.MacKey = PRF(masterSecret, seed, LabelKeyExpansion, ctx.HashFunc, 2*macKeyLength)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Mac Keys Length : %d , Mac Keys : %v", len(r.MacKey), r.MacKey)))

	r.ClientMacKey, r.ServerMacKey = r.MacKey[:macKeyLength], r.MacKey[macKeyLength:]
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Mac Keys Length : %d , Client Mac Keys : %v", len(r.ClientMacKey), r.ClientMacKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Mac Keys Length : %d , Server Mac Keys : %v", len(r.ServerMacKey), r.ServerMacKey)))
	return nil
}

// ParseClientKeyExchange 解析 ClientKeyExchange 消息
func ParseClientKeyExchange(data []byte, ctx *Context) (ClientKeyExchange, error) {
	var clientKeyExchange ClientKeyExchange
	switch ctx.KeyExchangeAlgorithm {
	case KeyExchangeRSA:
		clientKeyExchange = &RSAClientKeyExchange{}
	default:
		return nil, fmt.Errorf("unsupported Client Key Exchange Algorithm : %d", ctx.KeyExchangeAlgorithm)
	}
	if err := clientKeyExchange.Parse(data, ctx); err != nil {
		return nil, err
	}
	return clientKeyExchange, nil
}
