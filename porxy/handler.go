package porxy

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"net/url"
	"socks2https/connect"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/finger"
	"socks2https/porxy/https"
	"socks2https/porxy/socks"
	"socks2https/setting"
)

func Handler(reader *bufio.Reader, conn net.Conn, ctx *context.Context) {
	peek, err := reader.Peek(3)
	if err != nil {
		yaklog.Errorf("%s Failed to Pre Read Protocol Header : %v", ctx.LogTamplate, err)
		return
	}
	if peek[0] == socks.SOCKS5_VERSION {
		yaklog.Infof("%s Connection is SOCKS5 Tunnel.", ctx.LogTamplate)
		if err = socks.Handshake(reader, conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.LogTamplate, err)
			return
		}
		yaklog.Debugf("%s Finish SOCKS Handshake.", ctx.LogTamplate)
		if err = socks.Runcmd(reader, conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.LogTamplate, err)
			return
		}
		yaklog.Debugf("%s Finish SOCKS Command.", ctx.LogTamplate)
		if ctx.Cmd != socks.CONNECT_CMD {
			yaklog.Warnf("%s Not Support Command : %d", ctx.LogTamplate, ctx.Cmd)
			return
		}
	} else if string(peek) == http.MethodConnect[:3] {
		yaklog.Infof("%s Connection is HTTP Tunnel.", ctx.LogTamplate)
		if err = https.Handshake(reader, conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.LogTamplate, err)
			return
		}
	}

	if setting.Config.MITM.Switch {
		switch finger.Inspect(reader) {
		case finger.TLS:
			ctx.Protocol = finger.TLS
			if setting.Config.TLS.MITMSwitch {
				ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TLS"))
				ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TLS"))
				yaklog.Infof("%s Connection Protocol is TLS", ctx.LogTamplate)

				// 创建一个默认的 tls context 并加载配置文件配置
				ctx.TLSContext = context.NewTLSContext()
				if setting.Config.TLS.DefaultSNI != "" {
					ctx.TLSContext.SNI = setting.Config.TLS.DefaultSNI
				}

				connect.HandleTLSConnection(reader, conn, ctx)
				return
			}
		case finger.HTTP:
			ctx.Protocol = finger.HTTP
			if setting.Config.HTTP.MITMSwitch {
				ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "HTTP"))
				ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "HTTP"))
				yaklog.Infof("%s Connection Protocol is HTTP", ctx.LogTamplate)

				// 创建一个默认的 http context 并加载配置文件配置
				ctx.HTTPContext = context.NewHTTPContext()
				if setting.Config.HTTP.Proxy != "" {
					proxyURL, err := url.Parse(setting.Config.HTTP.Proxy)
					if err != nil {
						yaklog.Fatalf("Proxy URL is Invalid : %v", err)
					}
					ctx.HTTPContext.HttpClient.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
				}

				connect.HandleHTTPConnection(reader, conn, ctx)
				return
			}
		}
	}
	ctx.Protocol = finger.TCP
	ctx.Client2MitmLog = fmt.Sprintf("%s [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
	ctx.Mitm2ClientLog = fmt.Sprintf("%s [%s]", ctx.Mitm2ClientLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
	yaklog.Infof("%s Connection Protocol is TCP", ctx.LogTamplate)
	connect.Direct(reader, conn, ctx)
}
