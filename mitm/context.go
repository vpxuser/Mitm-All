package mitm

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"github.com/google/uuid"
	"hash"
)

type Context struct {
	ContextId            string
	LogTamplate          string
	Host                 string
	Port                 uint16
	Cmd                  uint8
	Client2MitmLog       string
	Mitm2ClientLog       string
	Client2TargetLog     string
	Target2ClientLog     string
	Version              uint16
	HandshakeType        uint8 //上下文临时存放的数据
	Domain               string
	CipherSuite          uint16
	HashFunc             func() hash.Hash
	KeyExchangeAlgorithm uint8
	KeyDER               *rsa.PrivateKey
	CertDER              *x509.Certificate
	HandshakeMessages    [][]byte
	ClientHello          Record
	ServerHello          Record
	Certificate          Record
	ServerHelloDone      Record
	ClientKeyExchange    Record
	Finished             Record
}

func NewContext() *Context {
	return &Context{
		ContextId:     uuid.New().String(),
		Version:       VersionTLS12,
		HandshakeType: 0xFF,
		CipherSuite:   TLS_RSA_WITH_AES_128_CBC_SHA,
		HashFunc:      sha1.New,
	}
}
