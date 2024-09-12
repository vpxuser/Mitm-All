package context

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/uuid"
	"hash"
	"net/http"
	"strings"
)

const (
	KeyExchangeRSA uint8 = iota
	KeyExchangeDHE
	KeyExchangeECDHE
	KeyExchangePSK
)

type TLSContext struct {
	Version           uint16
	HandshakeMessages [][]byte
	SNI               string
	ClientRandom      [32]byte
	ServerRandom      [32]byte
	KeyDER            *rsa.PrivateKey
	CertDER           *x509.Certificate
	CipherSuite       uint16
	KeyExchange       uint8
	MACLength         int
	BlockLength       int
	HashFunc          func() hash.Hash
	MasterSecret      []byte
	ClientMACKey      []byte
	ServerMACKey      []byte
	ClientKey         []byte
	ServerKey         []byte
	ClientIV          []byte
	ServerIV          []byte
	ClientEncrypted   bool
	ServerEncrypted   bool
	ClientSeqNum      uint64
	ServerSeqNum      uint64
	Protocol          string
}

func NewTLSContext(cipherSuite uint16, defaultSNI string) *TLSContext {
	ctx := &TLSContext{
		Version:     tls.VersionTLS12,
		SNI:         defaultSNI,
		CipherSuite: cipherSuite,
	}
	switch cipherSuite {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		ctx.KeyExchange = KeyExchangeRSA
		ctx.MACLength = 20
		ctx.BlockLength = 16
		ctx.HashFunc = sha1.New
	}
	return ctx
}

type HTTPContext struct {
	HttpClient *http.Client
	Request    *http.Request
	Response   *http.Response
}

func NewHTTPContext(transport *http.Transport) *HTTPContext {
	ctx := &HTTPContext{
		HttpClient: &http.Client{
			Transport: transport,
		},
	}
	return ctx
}

type Context struct {
	ContextId      string
	LogTamplate    string
	Host           string
	Port           uint16
	Cmd            uint8
	Client2MitmLog string
	Mitm2ClientLog string
	Mitm2TargetLog string
	Target2MitmLog string
	Protocol       string
	TLSContext     *TLSContext
	HTTPContext    *HTTPContext
}

func NewContext(cipherSuite uint16, defaultSNI string, transport *http.Transport) *Context {
	ctx := &Context{
		ContextId:   strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		TLSContext:  NewTLSContext(cipherSuite, defaultSNI),
		HTTPContext: NewHTTPContext(transport),
	}
	return ctx
}
