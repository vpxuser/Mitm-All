package protocol

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
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
	Parse(data []byte) error
	GetKeyAndIV(key *rsa.PrivateKey, clientRandom, serverRandom [32]byte, fnishedAlgorithm uint16) ([]byte, []byte, error)
}

// ClientKeyExchangeRSA 表示 RSA 密钥交换的 ClientKeyExchange
type ClientKeyExchangeRSA struct {
	PreMasterLength uint16
	PreMasterSecret []byte
}

// Parse 实现 ClientKeyExchange 接口的 Parse 方法
func (c *ClientKeyExchangeRSA) Parse(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("RSA ClientKeyExchange is invalid")
	}
	c.PreMasterLength = binary.BigEndian.Uint16(data[0:2])
	c.PreMasterSecret = data[2 : 2+c.PreMasterLength]
	//yaklog.Debugf("PreMasterLength: %d, PreMasterSecretLength: %d", len(data), c.PreMasterLength)
	return nil
}

// PRFSHA1 使用 HMAC-SHA1 实现 TLS PRF
func PRFSHA1(secret, seed []byte, label string, length int) []byte {
	hmacSHA1 := func(key, msg []byte) []byte {
		h := hmac.New(sha1.New, key)
		h.Write(msg)
		return h.Sum(nil)
	}
	var output []byte
	A := []byte(label)
	for len(output) < length {
		A = hmacSHA1(secret, A)
		output = append(output, hmacSHA1(secret, append(append(A, label...), seed...))...)
	}
	return output[:length]
}

func (c *ClientKeyExchangeRSA) GetKeyAndIV(key *rsa.PrivateKey, clientRandom, serverRandom [32]byte, finishedAlgorithm uint16) ([]byte, []byte, error) {
	if c.PreMasterLength == 0 {
		return nil, nil, fmt.Errorf("RSA ClientKeyExchange PreMaster Secret is invalid")
	}
	preMasterSecret, err := crypt.DecryptPKCS1RSA(key, c.PreMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	masterSecret := PRFSHA1(preMasterSecret, append(clientRandom[:], serverRandom[:]...), LabelMasterSecret, 48)
	//yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Client Random Length : %d , Server Random Length : %d , PreMaster Length : %d , MasterSecret Length : %d", len(clientRandom), len(serverRandom), len(preMasterSecret), len(masterSecret))))
	switch finishedAlgorithm {
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		keyBlock := PRFSHA1(masterSecret, append(serverRandom[:], clientRandom[:]...), LabelKeyExpansion, 32)
		return keyBlock[:16], keyBlock[16:32], nil
	default:
		return nil, nil, fmt.Errorf("unsupported RSA ClientKeyExchange Algorithm")
	}
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
