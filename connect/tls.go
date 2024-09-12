package connect

import (
	"bufio"
	"net"
	"socks2https/context"
	"socks2https/handler/tlshandler"
)

func HandleTLSConnection(reader *bufio.Reader, conn net.Conn, ctx *context.Context) {
	defer conn.Close()
	for _, tlsHandler := range tlshandler.TLSHandlers {
		if err := tlsHandler(reader, conn, ctx); err != nil {
			return
		}
	}
}
