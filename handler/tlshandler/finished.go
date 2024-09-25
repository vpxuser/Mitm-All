package tlshandler

import (
	"bufio"
	"crypto/hmac"
	"errors"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/crypt"
	"socks2https/pkg/tlsutils"
	"socks2https/setting"
)

var ReadFinished = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Finished"))

	record, err := tlsutils.FilterRecord(reader, tlsutils.ContentTypeHandshake, tlsutils.HandshakeTypeFinished, ctx)
	if err != nil {
		//yaklog.Errorf("%s %v", tamplate, err)
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return err
	}

	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, record.Fragment)

	if setting.Config.TLS.VerifyFinished {
		verifyData := tlsutils.VerifyPRF(ctx.TLSContext.Version, ctx.TLSContext.MasterSecret, []byte(crypt.LabelClientFinished), ctx.TLSContext.HandshakeMessages, 12)
		if hmac.Equal(verifyData, record.Handshake.Payload) {
			err = errors.New("Verify Client Finished Failed")
			yaklog.Errorf("%s %s", tamplate, err)
			return err
		}
		yaklog.Infof("%s Verify Client Finished Successfully", tamplate)
	} else {
		yaklog.Infof("%s Not Need to Verify Finished", tamplate)
	}
	return nil
})

var WriteFinished = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Finished"))
	blockRecord, err := tlsutils.NewBlockRecord(tlsutils.NewFinished(ctx), ctx)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	if _, err := conn.Write(blockRecord); err != nil {
		yaklog.Errorf("%s Failed to Write Server Finished : %v", tamplate, err)
		return err
	}

	yaklog.Infof("%s Successfully Write Server Finished.", tamplate)
	return nil
})
