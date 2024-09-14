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

var ReadChangeCipherSpec = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Change Cipher Spec"))
	if _, err := tlsutils.FilterRecord(reader, tlsutils.ContentTypeChangeCipherSpec, 0xff, ctx); err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}
	ctx.TLSContext.ClientEncrypted = true
	yaklog.Infof("%s Client Start Encrypt Fragment", tamplate)
	return nil
})

var WriteChangeCipherSpec = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Change Cipher Spec"))
	if _, err := conn.Write(tlsutils.NewChangeCipherSpec(ctx.TLSContext.Version).GetRaw()); err != nil {
		yaklog.Errorf("%s Write ChangeCipherSpec Failed : %v", tamplate, err)
		return err
	}
	yaklog.Infof("%s Server Start Encrypt Fragment", tamplate)
	return nil
})
