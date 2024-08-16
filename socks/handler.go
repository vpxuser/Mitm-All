package socks

import (
	"bufio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func handler(tag string, client net.Conn) {
	readWriter := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	if err := handshake(tag, readWriter); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks handshake", tag)
	cmd, addr, err := runcmd(tag, readWriter)
	if err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks command", tag)
	if cmd != CONNECT_CMD {
		return
	}
	if err = connect(tag, readWriter, client, addr); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s connection transfer fisished", tag)
}
