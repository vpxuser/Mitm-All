package socks

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/mitm"
	"socks2https/setting"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
)

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

// Run 启动socks5代理服务器
func Run() {
	server, err := net.Listen(PROTOCOL_TCP, setting.Host)
	if err != nil {
		yaklog.Fatalf("start SOCKS server failed : %v", err)
	}
	yaklog.Infof("start SOCKS server on [%s]", setting.Host)
	yaklog.Infof("connect to HTTP proxy [%s]", setting.Proxy)
	for {
		ctx := mitm.NewContext()
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
