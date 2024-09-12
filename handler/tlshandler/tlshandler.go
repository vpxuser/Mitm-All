package tlshandler

import (
	"bufio"
	"net"
	"socks2https/context"
)

type TLSHandler func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error

var TLSHandlers = []TLSHandler{
	ReadClientHello,
	WriteServerHello,
	WriteCertificate,
	WriteServerHelloDone,
	ReadClientKeyExchange,
	ReadChangeCipherSpec,
	ReadFinished,
	WriteChangeCipherSpec,
	WriteFinished,
	ReadApplicationData,
	WriteApplicationData,
}
