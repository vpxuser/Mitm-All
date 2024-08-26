package socks

import (
	"net"
)

func Connect(conn net.Conn, ctx *Context) error {
	return HeadProtocol(conn, ctx)
}
