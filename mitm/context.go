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
	"strings"
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
	HttpClient             *http.Client
	Request                *http.Request
	Response               *http.Response
	ModifyRequestPiPeLine  []ModifyRequest
	ModifyResponsePiPeLine []ModifyResponse
}

func NewContext(cipherSuite uint16) *Context {
	ctx := &Context{
		ContextId:   strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		Version:     tls.VersionTLS12,
		CipherSuite: cipherSuite,
		ConfigPath:  "config",
	}

	ctx.HttpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   setting.Config.Socks.TargetTimeout,
				KeepAlive: setting.Config.Socks.TargetTimeout,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: false,
		},
	}

	if setting.Config.HTTP.Proxy != "" {
		proxyURL, err := url.Parse(setting.Config.HTTP.Proxy)
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
