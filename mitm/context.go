package mitm

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/uuid"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"net"
	"net/http"
	"net/url"
	"socks2https/setting"
)

const (
	KB int = 1024
	MB int = 1024 * KB
	GB int = 1024 * MB
	TB int = 1024 * GB
)

type Context struct {
	ContextId              string
	LogTamplate            string
	Host                   string
	Port                   uint16
	Cmd                    uint8
	Client2MitmLog         string
	Mitm2ClientLog         string
	Client2TargetLog       string
	Target2ClientLog       string
	Version                uint16
	ClientRandom           [32]byte
	ServerRandom           [32]byte
	Domain                 string
	CipherSuite            uint16
	ConfigPath             string
	HashFunc               func() hash.Hash
	KeyExchangeAlgorithm   uint8
	KeyDER                 *rsa.PrivateKey
	CertDER                *x509.Certificate
	Cache                  []byte
	HandshakeMessages      [][]byte
	MACLength              int
	BlockLength            int
	PreMasterSecret        []byte
	MasterSecret           []byte
	SessionKey             []byte
	ClientMACKey           []byte
	ServerMACKey           []byte
	ClientKey              []byte
	ServerKey              []byte
	ClientIV               []byte
	ServerIV               []byte
	ClientEncrypted        bool
	ServerEncrypted        bool
	ClientSeqNum           uint64
	ServerSeqNum           uint64
	VerifyFinished         bool
	VerifyMAC              bool
	Proxy                  string
	HttpClient             *http.Client
	Request                *http.Request
	Response               *http.Response
	DNSServer              string
	ModifyRequestPiPeLine  []ModifyRequest
	ModifyResponsePiPeLine []ModifyResponse
	DefaultDomain          string
}

func NewContext(cipherSuite uint16) *Context {
	ctx := &Context{
		ContextId:      uuid.New().String()[:8],
		Version:        tls.VersionTLS12,
		CipherSuite:    cipherSuite,
		ConfigPath:     "config",
		VerifyMAC:      false,
		VerifyFinished: true,
		Proxy:          "http://127.0.0.1:8080",
		DNSServer:      "114.114.114.114",
		DefaultDomain:  "okii.com",
	}

	ctx.HttpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   setting.TargetTimeout,
				KeepAlive: setting.TargetTimeout,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: false,
		},
	}

	if ctx.Proxy != "" {
		proxyURL, err := url.Parse(ctx.Proxy)
		if err != nil {
			yaklog.Fatalf("Proxy URL is Invalid : %v", err)
		}
		ctx.HttpClient.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
	}

	switch cipherSuite {
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		ctx.MACLength = 20
		ctx.BlockLength = 16
		ctx.HashFunc = sha1.New
	}
	return ctx
}
