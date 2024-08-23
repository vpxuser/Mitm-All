package socks

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

var Tag string

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

func Fastboot() {
	defaultConfig := &MitmSocks{
		Host: "0.0.0.0",
		Port: 1080,
		Cert: "config/ca.cert",
		Key:  "config/ca.key",
	}
	defaultAddr := fmt.Sprintf("%s:%d", defaultConfig.Host, defaultConfig.Port)
	server, err := net.Listen("tcp", defaultAddr)
	if err != nil {
		yaklog.Fatalf("SOCKS Server start failed : %v", err)
	}
	yaklog.Infof("SOCKS Server start on [%s]", defaultAddr)
	for {
		defaultConfig.Tag = fmt.Sprintf("[%s]", uuid.New().String())
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("%s accept Client connection failed : %v", defaultConfig.Tag, err)
			continue
		}
		defaultConfig.Tag = fmt.Sprintf("[%s] %s", client.RemoteAddr().String(), defaultConfig.Tag)
		yaklog.Infof("%s accept Client connection", defaultConfig.Tag)
		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
			yaklog.Warnf("%s set Client deadline failed : %v", defaultConfig.Tag, err)
		}
		go Handler(client)
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
		clientId := uuid.New().String()
		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("[%s] accept Client connection failed : %v", clientId, err)
			continue
		}
		clientIP := client.RemoteAddr().String()
		Tag = fmt.Sprintf("[%s] [%s]", clientId, clientIP)
		yaklog.Infof("%s accept Client connection", Tag)
		if err = client.SetDeadline(time.Now().Add(setting.ClientTimeout)); err != nil {
			yaklog.Warnf("%s set Client deadline failed : %v", Tag, err)
		}
		go Handler(client)
	}
}
