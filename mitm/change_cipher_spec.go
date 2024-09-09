package mitm

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/comm"
)

func NewChangeCipherSpec(ctx *Context) *Record {
	return &Record{
		ContentType: ContentTypeChangeCipherSpec,
		Version:     ctx.Version,
		Length:      1,
		Fragment:    []byte{0x01},
	}
}

var ReadChangeCipherSpec = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Change Cipher Spec"))
	if _, err := FilterRecord(reader, ContentTypeChangeCipherSpec, 0xff, ctx); err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	ctx.ClientEncrypted = true
	yaklog.Infof("%s Client Start Encrypt Fragment", tamplate)
	return nil
})

var WriteChangeCipherSpec = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Change Cipher Spec"))
	if _, err := conn.Write(NewChangeCipherSpec(ctx).GetRaw()); err != nil {
		return fmt.Errorf("%s Write ChangeCipherSpec Failed : %v", tamplate, err)
	}
	yaklog.Debugf("%s Server Start Encrypt Fragment", tamplate)
	return nil
})
