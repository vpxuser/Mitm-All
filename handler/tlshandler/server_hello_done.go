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

var WriteServerHelloDone = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Server Hello Done"))
	record := tlsutils.NewServerHelloDone(ctx.TLSContext.Version)
	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, record.Fragment)
	if _, err := conn.Write(record.GetRaw()); err != nil {
		yaklog.Errorf("%s Write ServerHelloDone Failed : %v", tamplate, err)
		return err
	}
	yaklog.Infof("%s Write ServerHelloDone Successfully.", tamplate)
	return nil
})
