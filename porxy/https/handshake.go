package https

import (
	"bufio"
	"fmt"
	"net"
	"socks2https/context"
	"socks2https/pkg/httptools"
)

func Handshake(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	connectReq, err := httptools.ReadRequest(reader, "http")
	if err != nil {
		return fmt.Errorf("Failed to Read HTTP CONNECT Request : %v", err)
	}

	ctx.Host, ctx.Port, err = httptools.ParseHostAndPort(connectReq.Host)
	if err != nil {
		return err
	}

	if err = httptools.NewConnectResponse().Write(conn); err != nil {
		return fmt.Errorf("Failed to Write HTTP CONNECT Response : %v", err)
	}

	return nil
}
