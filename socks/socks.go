package socks

import (
	"fmt"
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
	addr := fmt.Sprintf("%s:%s", setting.Config.Host, setting.Config.Socks.Port)
	server, err := net.Listen(PROTOCOL_TCP, addr)
	if err != nil {
		yaklog.Fatalf("start socks server failed : %v", err)
	}
	yaklog.Infof("start server socks listen on [%s]", addr)
	for {
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("accept client connect failed : %v", err)
			continue
		}
		yaklog.Infof("recive client connect from [%s]", client.RemoteAddr().String())
		_ = client.SetDeadline(time.Now().Add(setting.Config.Socks.Client.Timeout * time.Second))
		go handler(client)
	}
}
