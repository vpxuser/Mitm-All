package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func handler(src net.Conn) {
	defer func() {
		if err := src.Close(); err != nil {
			yaklog.Errorf("src close failed : %v", err)
		}
	}()
	if err := handshake(src); err != nil {
		yaklog.Errorf("client [%s] socks handshake failed : %v", src.RemoteAddr().String(), err)
		return
	}
	yaklog.Infof("client [%s] finish socks handshake", src.RemoteAddr().String())
	dst, protocol, rep, err := connect(src)
	if err != nil || dst == nil {
		_ = failure(src, rep)
		yaklog.Errorf("client [%s] connect to target host failed : %v", src.RemoteAddr().String(), err)
		return
	}
	defer func() {
		if err = dst.Close(); err != nil {
			yaklog.Errorf("dst close failed : %v", err)
		}
	}()
	_ = success(src)
	yaklog.Infof("client [%s] connect to target host finished", src.RemoteAddr().String())
	if err = forward(protocol, src, dst); err != nil {
		yaklog.Errorf("client [%s] send to message to target host failed : %v", src.RemoteAddr().String(), err)
	}
	yaklog.Infof("client [%s] send to message to target host fisished", src.RemoteAddr().String())
}
