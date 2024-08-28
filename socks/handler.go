package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func Handler(conn net.Conn, ctx *Context) {
	if err := handShake(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Infof("%s finish socks handshake", ctx.LogTamplate)
	if err := Runcmd(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Infof("%s finish socks command", ctx.LogTamplate)
	switch ctx.Cmd {
	case CONNECT_CMD:
		if err := Connect(conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.LogTamplate, err)
			return
		}
	default:
		yaklog.Warnf("%s not support CMD : %d", ctx.LogTamplate, ctx.Cmd)
		return
	}
	yaklog.Infof("%s connection transfer fisished", ctx.LogTamplate)
}
