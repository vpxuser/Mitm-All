package tsocks

import (
	"bufio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/comm"
)

func handler(tag string, client net.Conn) {
	tag = comm.SetColor(comm.GREEN_COLOR_TYPE, tag)
	if err := handshake(tag, client); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks handshake", tag)
	server, err := connect(tag, client)
	if err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks command", tag)
	if err = forward(tag, client, server); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s connection transfer fisished", tag)
}

func handlerReader(tag string, client net.Conn) {
	tag = comm.SetColor(comm.YELLOW_COLOR_TYPE, tag)
	reader := bufio.NewReader(client)
	if err := handshakeReader(tag, reader, client); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks handshake", tag)
	server, err := connectReader(tag, reader, client)
	if err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks command", tag)
	if err = forwardReader(tag, reader, client, server); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s connection transfer fisished", tag)
}

func handlerReadWriter(tag string, client net.Conn) {
	tag = comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, tag))
	readWriter := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	if err := handshakeReadWriter(tag, readWriter); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks handshake", tag)
	server, err := connectReadWriter(tag, readWriter)
	if err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s finish socks command", tag)
	_, err = parseProtocol(tag, readWriter)
	if err != nil {
		yaklog.Error(err)
		return
	}
	if err = forwardReadWriter(tag, readWriter, client, server); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s connection transfer fisished", tag)
}
