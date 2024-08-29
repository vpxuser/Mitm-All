package socks

import (
	"net"
	"socks2https/mitm"
)

func Connect(conn net.Conn, ctx *mitm.Context) error {
	return mitm.HeadProtocol(conn, ctx)
}
