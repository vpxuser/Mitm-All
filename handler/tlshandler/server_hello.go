package tlshandler

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/tlsutils"
)

var WriteServerHello = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Server Hello"))
	record, err := tlsutils.NewServerHello(ctx.TLSContext.Version, ctx.TLSContext.CipherSuite)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}
	ctx.TLSContext.ServerRandom = record.Handshake.ServerHello.Random
	serverHello := record.GetRaw()
	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, serverHello[5:])
	if _, err = conn.Write(serverHello); err != nil {
		yaklog.Errorf("%s Write ServerHello Failed : %v", tamplate, err)
		return err
	}
	yaklog.Infof("%s Write ServerHello Successfully", tamplate)
	return nil
})
