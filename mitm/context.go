package mitm

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"github.com/google/uuid"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"net/http"
	"net/url"
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
	ClientRandom         [32]byte
	ServerRandom         [32]byte
	Domain               string
	CipherSuite          uint16
	HashFunc             func() hash.Hash
	KeyExchangeAlgorithm uint8
	KeyDER               *rsa.PrivateKey
	CertDER              *x509.Certificate
	Cache                []byte
	HandshakeMessages    [][]byte
	MACLength            int
	BlockLength          int
	PreMasterSecret      []byte
	MasterSecret         []byte
	KeyBlock             []byte
	ClientMACKey         []byte
	ServerMACKey         []byte
	ClientKey            []byte
	ServerKey            []byte
	ClientIV             []byte
	ServerIV             []byte
	ClientEncrypted      bool
	ServerEncrypted      bool
	ClientSeqNum         uint64
	ServerSeqNum         uint64
	VerifyFinished       bool
	VerifyMAC            bool
	Proxy                string
	HttpClient           *http.Client
	Request              *http.Request
	Response             *http.Response
	DNSServer            string
	RequestMITMPiPeLine  []ModifyRequest
	ResponseMITMPiPeLine []ModifyResponse
}

func NewContext(cipherSuite uint16) *Context {
	ctx := &Context{
		ContextId:      uuid.New().String(),
		Version:        VersionTLS102,
		CipherSuite:    cipherSuite,
		VerifyMAC:      true,
		VerifyFinished: true,
		Proxy:          "http://127.0.0.1:8081",
		DNSServer:      "8.8.8.8",
	}
	proxyURL, err := url.Parse(ctx.Proxy)
	if err != nil {
		yaklog.Fatalf("Proxy URL is invalid : %v", err)
	}
	ctx.HttpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	switch cipherSuite {
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		ctx.MACLength = 20
		ctx.BlockLength = 16
		ctx.HashFunc = sha1.New
	}
	return ctx
}
