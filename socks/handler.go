package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func Handler(client net.Conn) {
	if err := Handshake(client); err != nil {
		yaklog.Errorf("%s %v", Tag, err)
		return
	}
	yaklog.Infof("%s finish socks handshake", Tag)
	cmd, addr, err := runcmd(client)
	if err != nil {
		yaklog.Errorf("%s %v", Tag, err)
		return
	}
	yaklog.Infof("%s finish socks command", Tag)
	if cmd != CONNECT_CMD {
		yaklog.Warnf("%s not support CMD : %d", Tag, cmd)
		return
	}
	if err = connect(client, addr); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s connection transfer fisished", Tag)
}
