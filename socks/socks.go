package socks

import (
	"fmt"
	"github.com/google/uuid"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/protocol"
	"socks2https/setting"
	"sync"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
)

type Context struct {
	Mutex        sync.Mutex
	ClientId     string
	LogTamplate  string
	Host         string
	Port         uint16
	Domain       string
	Cmd          uint8
	ClientHello  protocol.Record
	Encrypted    bool
	ClientRandom [32]byte
	ServerRandom [32]byte
	Key          []byte
	IV           []byte
	RecordList   [][]byte
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

//func Fastboot() {
//	defaultConfig := &MitmSocks{
//		Host: "0.0.0.0",
//		Port: 1080,
//		Cert: "config/ca.cert",
//		Key:  "config/ca.key",
//	}
//	defaultAddr := fmt.Sprintf("%s:%d", defaultConfig.Host, defaultConfig.Port)
//	server, err := net.Listen("tcp", defaultAddr)
//	if err != nil {
//		yaklog.Fatalf("SOCKS Server start failed : %v", err)
//	}
//	yaklog.Infof("SOCKS Server start on [%s]", defaultAddr)
//	for {
//		defaultConfig.Tag = fmt.Sprintf("[%s]", uuid.New().String())
//		client, err := server.Accept()
//		if err != nil {
//			yaklog.Errorf("%s accept Client connection failed : %v", defaultConfig.Tag, err)
//			continue
//		}
//		defaultConfig.Tag = fmt.Sprintf("[%s] %s", client.RemoteAddr().String(), defaultConfig.Tag)
//		yaklog.Infof("%s accept Client connection", defaultConfig.Tag)
//		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
//			yaklog.Warnf("%s set Client deadline failed : %v", defaultConfig.Tag, err)
//		}
//		go Handler(client)
//	}
//}

func (c *Context) GetClientId() string {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return c.ClientId
}

func (c *Context) SetDomain(domain string) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	c.Domain = domain
}

func (c *Context) GetDomain() string {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return c.Domain
}

func (c *Context) SetClientHello(clientHello *protocol.Record) {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	c.ClientHello = *clientHello
}

func (c *Context) GetClientHello() *protocol.Record {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return &c.ClientHello
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
		ctx := &Context{ClientId: fmt.Sprintf("[clientId:%s]", uuid.New().String())}
		ctx.LogTamplate = ctx.ClientId
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("[%s] accept Client connection failed : %v", ctx.LogTamplate, err)
			continue
		}
		ctx.LogTamplate = fmt.Sprintf("%s [clientIP:%s]", ctx.LogTamplate, client.RemoteAddr().String())
		yaklog.Infof("%s accept Client connection", ctx.LogTamplate)
		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
			yaklog.Warnf("%s set Client deadline failed : %v", ctx.LogTamplate, err)
		}
		go Handler(client, ctx)
	}
}
