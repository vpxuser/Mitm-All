package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/mitm"
)

func Handler(conn net.Conn, ctx *mitm.Context) {
	if err := Handshake(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Debugf("%s Finish SOCKS Handshake", ctx.LogTamplate)
	if err := Runcmd(conn, ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.LogTamplate, err)
		return
	}
	yaklog.Infof("%s Finish SOCKS Command", ctx.LogTamplate)
	switch ctx.Cmd {
	case CONNECT_CMD:
		if err := Connect(conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.LogTamplate, err)
			return
		}
	default:
		yaklog.Warnf("%s Not Support CMD : %d", ctx.LogTamplate, ctx.Cmd)
		return
	}
	yaklog.Infof("%s Transfer Finished", ctx.LogTamplate)
}
