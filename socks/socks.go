package socks

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"github.com/google/uuid"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"net"
	"socks2https/setting"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
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
	HandshakeType        uint8 //上下文临时存放的数据
	Domain               string
	CipherSuite          uint16
	HashFunc             func() hash.Hash
	KeyExchangeAlgorithm uint8
	KeyDER               *rsa.PrivateKey
	CertDER              *x509.Certificate
	HandshakeRawList     [][]byte
	ClientHello          Record
	ServerHello          Record
	Certificate          Record
	ServerHelloDone      Record
	ClientKeyExchange    Record
	Finished             Record
}

type MitmSocks struct {
	Tag   string
	Host  string
	Port  uint16
	Proxy struct {
		Host string
		Port uint16
	}
	Cert string
	Key  string
}

func NewContext() *Context {
	return &Context{
		ContextId:     uuid.New().String(),
		HandshakeType: 0xFF,
		CipherSuite:   TLS_RSA_WITH_AES_128_CBC_SHA,
		HashFunc:      sha1.New,
	}
}

// Run 启动socks5代理服务器
func Run() {
	server, err := net.Listen(PROTOCOL_TCP, setting.Host)
	if err != nil {
		yaklog.Fatalf("start SOCKS server failed : %v", err)
	}
	yaklog.Infof("start SOCKS server on [%s]", setting.Host)
	yaklog.Infof("connect to HTTP proxy [%s]", setting.Proxy)
	for {
		ctx := NewContext()
		ctx.LogTamplate = fmt.Sprintf("[%s]", ctx.ContextId)
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("%s accept Client connection failed : %v", ctx.LogTamplate, err)
			continue
		}
		ctx.LogTamplate = fmt.Sprintf("%s [clientIP:%s]", ctx.LogTamplate, client.RemoteAddr().String())
		ctx.Client2MitmLog = fmt.Sprintf("[%s] [%s ==> %s]", ctx.ContextId, client.RemoteAddr().String(), client.LocalAddr().String())
		ctx.Mitm2ClientLog = fmt.Sprintf("[%s] [%s ==> %s]", ctx.ContextId, client.LocalAddr().String(), client.RemoteAddr().String())
		yaklog.Infof("%s accept Client connection", ctx.LogTamplate)
		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
			yaklog.Warnf("%s set Client deadline failed : %v", ctx.LogTamplate, err)
		}
		go Handler(client, ctx)
	}
}
