package connect

import (
	"bufio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
	"socks2https/mitm"
	"socks2https/pkg/httptools"
)

func HandleHTTPConnection(reader *bufio.Reader, conn net.Conn, ctx *context.Context) {
	defer conn.Close()
	var err error
	ctx.HTTPContext.Request, err = httptools.ReadRequest(reader, "http")
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}

	if err = mitm.HandleHTTPFragment(ctx); err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}

	yaklog.Infof("%s Successfully Write HTTP Request.", ctx.Client2MitmLog)

	if err = ctx.HTTPContext.Response.Write(conn); err != nil {
		yaklog.Errorf("%s Write HTTP Response Failed : %v", ctx.Mitm2ClientLog, err)
		return
	}

	yaklog.Infof("%s Successfully Write HTTP Response.", ctx.Mitm2ClientLog)
}
