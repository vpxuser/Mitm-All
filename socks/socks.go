package socks

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"regexp"
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
	server, err := net.Listen(PROTOCOL_TCP, setting.Config.Socks.Host)
	if err != nil {
		yaklog.Fatalf("Start SOCKS Server Failed : %v", err)
	}
	yaklog.Infof("Start SOCKS Server On [%s]", setting.Config.Socks.Host)
	for {
		ctx := mitm.NewContext(mitm.TLS_RSA_WITH_AES_128_CBC_SHA)
		ctx.LogTamplate = fmt.Sprintf("[clientId:%s]", ctx.ContextId)
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("%s Accept Client Connection Failed : %v", ctx.LogTamplate, err)
			continue
		}
		ctx.LogTamplate = fmt.Sprintf("%s [clientIP:%s]", ctx.LogTamplate, client.RemoteAddr().String())
		reg := regexp.MustCompile(`:\d+$`)
		ctx.Client2MitmLog = fmt.Sprintf("[clientId:%s] [%s => %s]", ctx.ContextId, client.RemoteAddr().String(), reg.FindString(client.LocalAddr().String()))
		ctx.Mitm2ClientLog = fmt.Sprintf("[clientId:%s] [%s => %s]", ctx.ContextId, reg.FindString(client.LocalAddr().String()), client.RemoteAddr().String())
		yaklog.Debugf("%s Accept Client Connection", ctx.LogTamplate)
		if err = client.SetDeadline(time.Now().Add(setting.Config.Socks.ClientTimeout)); err != nil {
			yaklog.Warnf("%s Set Client Deadline Failed : %v", ctx.LogTamplate, err)
		}
		go Handler(client, ctx)
	}
}
