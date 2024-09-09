package mitm

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/comm"
)

func NewServerHelloDone(ctx *Context) *Record {
	handshake := &Handshake{
		HandshakeType: HandshakeTypeServerHelloDone,
		Length:        0,
	}
	handshakeRaw := handshake.GetRaw()
	//yaklog.Debugf("handshake raw: %s", comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%v", handshakeRaw)))
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     ctx.Version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}
}

var WriteServerHelloDone = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"), comm.SetColor(comm.RED_COLOR_TYPE, "Server Hello Done"))
	record := NewServerHelloDone(ctx)
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	if _, err := conn.Write(record.GetRaw()); err != nil {
		return fmt.Errorf("%s Write ServerHelloDone Failed : %v", tamplate, err)
	}
	yaklog.Infof("%s Write ServerHelloDone Successfully", tamplate)
	return nil
})
