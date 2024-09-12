package tlshandler

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http/httputil"
	"socks2https/context"
	"socks2https/mitm"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/finger"
	"socks2https/pkg/httptools"
	"socks2https/pkg/tlsutils"
)

var ReadApplicationData = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Application Data"))

	record, err := tlsutils.FilterRecord(reader, tlsutils.ContentTypeApplicationData, 0xff, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	yaklog.Infof("%s Successfully Read Application Data.", tamplate)

	switch finger.Inspect(bufio.NewReader(bytes.NewReader(record.Fragment[:7]))) {
	case finger.HTTP:
		ctx.TLSContext.Protocol = finger.HTTP
		ctx.HTTPContext.Request, err = httptools.ReadRequest(bufio.NewReader(bytes.NewReader(record.Fragment)), "https")
		if err != nil {
			yaklog.Errorf("%s %v", tamplate, err)
			return err
		}

		if err := mitm.HandleHTTPFragment(ctx); err != nil {
			yaklog.Errorf("%s %v", tamplate, err)
			return err
		}
	default:
		err = errors.New("Not Support Application Data Protocol")
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	return nil
})

var WriteApplicationData = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Application Data"))

	var fragment []byte
	var err error
	switch ctx.TLSContext.Protocol {
	case finger.HTTP:
		fragment, err = httputil.DumpResponse(ctx.HTTPContext.Response, true)
		if err != nil {
			yaklog.Errorf("%s Writing Request Failed : %v", tamplate, err)
			return err
		}
	default:
		err = errors.New("Not Support TLS Protocol")
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	record, err := tlsutils.NewApplicationData(ctx.TLSContext.Version, fragment)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	blockRecord, err := tlsutils.NewBlockRecord(record, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}

	if _, err = conn.Write(blockRecord); err != nil {
		yaklog.Errorf("%s Failed to Write Application Data : %v", tamplate, err)
		return err
	}

	yaklog.Infof("%s Successfully Write Application Data.", tamplate)

	blockRecord, err = tlsutils.NewBlockRecord(tlsutils.NewAlert(ctx.TLSContext.Version, tlsutils.AlertLevelWarning, tlsutils.AlertDescriptionCloseNotify), ctx)
	if err != nil {
		yaklog.Errorf("%s %v", tamplate, err)
		return err
	}
	if _, err = conn.Write(blockRecord); err != nil {
		yaklog.Errorf("%s Failed to Write Alert : %v", tamplate, err)
		return err
	}
	return nil
})
