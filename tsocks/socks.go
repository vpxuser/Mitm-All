package tsocks

import (
	"fmt"
	"github.com/google/uuid"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/setting"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
)

var ProxySwitch bool

// Run 启动socks5代理服务器
func Run(port int, ioType int, proxySwitch bool) {
	ProxySwitch = proxySwitch
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	server, err := net.Listen(PROTOCOL_TCP, addr)
	if err != nil {
		yaklog.Fatalf("start SOCKS server failed : %v", err)
	}
	yaklog.Infof("start SOCKS server on [%s]", addr)
	for {
		clientId := uuid.New().String()
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("[%s] accept Client connection failed : %v", clientId, err)
			continue
		}
		clientIP := client.RemoteAddr().String()
		tag := fmt.Sprintf("[%s] [%s] [%s]", "TSocks", clientId, clientIP)
		yaklog.Infof("%s accept Client connection", tag)
		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
			yaklog.Warnf("%s set Client deadline failed : %v", tag, err)
		}
		switch ioType {
		case 1:
			go handlerReader(tag, client)
		case 2:
			go handlerReadWriter(tag, client)
		default:
			go handler(tag, client)
		}
	}
}
