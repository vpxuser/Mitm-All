package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
)

func Handler(conn net.Conn, ctx *context.Context) {
	if err := Handshake(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Debugf("%s Finish SOCKS Handshake.", ctx.LogTamplate)
	if err := Runcmd(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Debugf("%s Finish SOCKS Command.", ctx.LogTamplate)
	switch ctx.Cmd {
	case CONNECT_CMD:
		Connect(conn, ctx)
	default:
		yaklog.Warnf("%s Not Support Command : %d", ctx.LogTamplate, ctx.Cmd)
	}
}
