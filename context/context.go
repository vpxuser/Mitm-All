package context

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/uuid"
	"hash"
	"net"
	"net/http"
	"strings"
	"time"
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

// NewTLSContext 创建一个默认的 tls context
func NewTLSContext() *TLSContext {
	return &TLSContext{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		KeyExchange: KeyExchangeRSA,
		MACLength:   20,
		BlockLength: 16,
		HashFunc:    sha1.New,
	}
}

type HTTPContext struct {
	HttpClient *http.Client
	Request    *http.Request
	Response   *http.Response
}

// NewHTTPContext 创建一个默认的 http context
func NewHTTPContext() *HTTPContext {
	return &HTTPContext{
		HttpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   15 * time.Second,
					KeepAlive: 15 * time.Second,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				ForceAttemptHTTP2: false,
			},
		},
	}
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

// NewContext 创建一个默认的 context
func NewContext() *Context {
	return &Context{
		ContextId: strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
	}
}
