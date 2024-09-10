package socks

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"socks2https/mitm"
	"socks2https/pkg/color"
	"strings"
)

func Connect(conn net.Conn, ctx *mitm.Context) error {
	reader := bufio.NewReader(conn)
	header, err := reader.Peek(3)
	if err != nil {
		return fmt.Errorf("read Protocol Header failed : %v", err)
	}
	maybeTLS := false
	if _, ok := mitm.ContentType[header[0]]; ok {
		maybeTLS = true
	} else if httpMethod, ok := mitm.HttpMethod[strings.TrimSpace(string(header))]; ok {
		ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "HTTP"))
		ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "HTTP"))
		ctx.Client2TargetLog = fmt.Sprintf("%s [%s]", ctx.Client2TargetLog, color.SetColor(color.YELLOW_COLOR_TYPE, "HTTP"))
		ctx.Target2ClientLog = fmt.Sprintf("%s [%s]", ctx.Target2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "HTTP"))
		if httpMethod == http.MethodConnect {
			yaklog.Infof("%s %s", ctx.LogTamplate, color.SetColor(color.RED_COLOR_TYPE, "Connection Protocol is HTTP CONNECT Tunnel"))
		}
		yaklog.Infof("%s %s", ctx.LogTamplate, color.SetColor(color.YELLOW_COLOR_TYPE, "Connection Protocol is HTTP"))
		mitm.HTTPMITM(reader, conn, ctx)
		return nil
	}
	if maybeTLS {
		ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TLS"))
		ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TLS"))
		ctx.Client2TargetLog = fmt.Sprintf("%s [%s]", ctx.Client2TargetLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TLS"))
		ctx.Target2ClientLog = fmt.Sprintf("%s [%s]", ctx.Target2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TLS"))
		version := binary.BigEndian.Uint16(header[1:3])
		if version >= tls.VersionSSL30 && version <= tls.VersionTLS13 {
			yaklog.Infof("%s %s", ctx.LogTamplate, color.SetColor(color.RED_COLOR_TYPE, "Connection Protocol is TLS"))
			mitm.TLSMITM(reader, conn, ctx)
			return nil
		}
	}
	ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TCP"))
	ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TCP"))
	ctx.Client2TargetLog = fmt.Sprintf("%s [%s]", ctx.Client2TargetLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TCP"))
	ctx.Target2ClientLog = fmt.Sprintf("%s [%s]", ctx.Target2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "TCP"))
	yaklog.Infof("%s Connection Protocol is TCP", ctx.LogTamplate)
	return mitm.TCPMITM(reader, conn, ctx)
}
