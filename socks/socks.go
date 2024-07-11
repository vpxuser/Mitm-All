package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/setting"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
)

// Run 启动socks5代理服务器
func Run() {
	server, err := net.Listen(PROTOCOL_TCP, setting.Host)
	if err != nil {
		yaklog.Fatalf("start socks server failed : %v", err)
	}
	yaklog.Infof("start server socks listen on [%s]", setting.Host)
	yaklog.Infof("upstream proxy is : %s", setting.Proxy)
	for {
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("accept client connect failed : %v", err)
			continue
		}
		yaklog.Infof("recive client connect from [%s]", client.RemoteAddr().String())
		_ = client.SetDeadline(time.Now().Add(setting.ClientTimeout))
		go handler(client)
	}
}
