package socks

import (
	"bufio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func handler(tag string, client net.Conn) {
	defer client.Close()
	clientReader := bufio.NewReader(client)
	if err := handshake(tag, clientReader, client); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s Client finish socks handshake", tag)
	//server, protocol, rep, err := connect(tag, clientReader)
	//if err != nil || server == nil {
	//	yaklog.Error(err)
	//	if err = failure(tag, client, rep); err == nil {
	//		yaklog.Warn(err)
	//	}
	//	return
	//}
	addr, rep, err := parseAddress(tag, clientReader)
	if err != nil {
		yaklog.Error(err)
		_ = failure(tag, client, rep)
		return
	}
	//defer func() {
	//	if err = server.Close(); err != nil {
	//		yaklog.Errorf("%s Server close failed : %v", tag, err)
	//	}
	//}()
	//if err = success(tag, client); err != nil {
	//	yaklog.Warn(err)
	//}
	_ = success(tag, client)
	yaklog.Infof("%s Client connect to Target", tag)
	if err = forward(tag, clientReader, client, addr); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s Client send message to Target fisished", tag)
}
