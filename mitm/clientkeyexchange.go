package mitm

import (
	"crypto/hmac"
	"crypto/sha256"
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
	KeyBlock                []byte
	ClientKey               []byte
	ServerKey               []byte
	ClientIV                []byte
	ServerIV                []byte
	MacKey                  []byte
	ClientMacKey            []byte
	ServerMacKey            []byte
}

func HmacHash(secret, A []byte, hashFunc func() hash.Hash) []byte {
	hmacFunc := hmac.New(hashFunc, secret)
	hmacFunc.Write(A)
	return hmacFunc.Sum(nil)
}

func PHash(secret, seed []byte, outputLength int, hashFunc func() hash.Hash) []byte {
	var result []byte
	A := seed
	for len(result) < outputLength {
		A = HmacHash(secret, A, hashFunc)
		result = append(result, HmacHash(secret, append(A, seed...), hashFunc)...)
	}
	return result
}

func TLS12PRF(secret, label, seed []byte, outputLength int, hashFunc func() hash.Hash) []byte {
	return PHash(secret, append(label, seed...), outputLength, hashFunc)[:outputLength]
}

func PRF(secret, label, seed []byte, length int) []byte {
	switch binary.BigEndian.Uint16(secret[:2]) {
	case VersionTLS12:
		return TLS12PRF(secret, label, seed, length, sha256.New)
	default:
		return TLS12PRF(secret, label, seed, length, sha256.New)
	}
}

// Parse 实现 ClientKeyExchange 接口的 Parse 方法
func (r *RSAClientKeyExchange) Parse(data []byte, ctx *Context) error {
	if len(data) < 2 {
		return fmt.Errorf("RSA ClientKeyExchange is invalid")
	}
	r.EncrypedPreMasterLength = binary.BigEndian.Uint16(data[0:2])
	r.EncrypedPreMasterSecret = data[2 : 2+r.EncrypedPreMasterLength]
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Encrypted PreMasterSecret Length : %d , Encrypted PreMasterSecret : %v", len(r.EncrypedPreMasterSecret), r.EncrypedPreMasterSecret)))

	preMasterSecret, err := crypt.DecryptRSAPKCS(ctx.KeyDER, r.EncrypedPreMasterSecret)
	if err != nil {
		return fmt.Errorf("RSA Decryption failed : %v", err)
	}
	r.PreMasterSecret = preMasterSecret
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("PreMasterSecret Length : %d , PreMasterSecret : %v", len(preMasterSecret), preMasterSecret)))

	yaklog.Debugf("Client Random : %v", ctx.ClientHello.Handshake.ClientHello.Random)
	yaklog.Debugf("Server Random : %v", ctx.ServerHello.Handshake.ServerHello.Random)
	seed := append(ctx.ClientHello.Handshake.ClientHello.Random[:], ctx.ServerHello.Handshake.ServerHello.Random[:]...)
	masterSecret := PRF(preMasterSecret, []byte(LabelMasterSecret), seed, len(preMasterSecret))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("MasterSecret Length : %d , MasterSecret : %v", len(masterSecret), masterSecret)))
	r.MasterSecret = masterSecret

	macKeyLength, keyLength, ivLength := 0, 0, 0
	switch ctx.CipherSuite {
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		macKeyLength, keyLength, ivLength = 20, 16, 16
	}

	seed = append(ctx.ServerHello.Handshake.ServerHello.Random[:], ctx.ClientHello.Handshake.ClientHello.Random[:]...)
	r.KeyBlock = PRF(masterSecret, []byte(LabelKeyExpansion), seed, 2*(macKeyLength+keyLength+ivLength))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Key Expansion Length : %d , Key Expansion : %v", len(r.KeyBlock), r.KeyBlock)))

	r.ClientMacKey, r.ServerMacKey, r.ClientKey, r.ServerKey, r.ClientIV, r.ServerIV = r.KeyBlock[:macKeyLength], r.KeyBlock[macKeyLength:2*macKeyLength], r.KeyBlock[2*macKeyLength:2*macKeyLength+keyLength], r.KeyBlock[2*macKeyLength+keyLength:2*macKeyLength+2*keyLength], r.KeyBlock[2*macKeyLength+2*keyLength:2*macKeyLength+2*keyLength+ivLength], r.KeyBlock[2*macKeyLength+2*keyLength+ivLength:]
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Mac Keys Length : %d , Client Mac Keys : %v", len(r.ClientMacKey), r.ClientMacKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Mac Keys Length : %d , Server Mac Keys : %v", len(r.ServerMacKey), r.ServerMacKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Key Length : %d , Client Key : %v", len(r.ClientKey), r.ClientKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server Key Length : %d , Server Key : %v", len(r.ServerKey), r.ServerKey)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client IV Length : %d , Client IV : %v", len(r.ClientIV), r.ClientIV)))
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Server IV Length : %d , Server IV : %v", len(r.ServerIV), r.ServerIV)))
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
