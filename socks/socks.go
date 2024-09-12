package socks

import (
	"crypto/tls"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/setting"
	"time"
)

const (
	PROTOCOL_TCP  = "tcp"
	PROTOCOL_HTTP = "http"
)

type MITMSocks struct {
	Host          string
	Proxy         string
	ClientTimeout time.Duration
	TargetTimeout time.Duration
	DefaultSNI    string
}

func (m *MITMSocks) Run() {
	server, err := net.Listen(PROTOCOL_TCP, m.Host)
	if err != nil {
		yaklog.Fatalf("Start SOCKS Server Failed : %v", err)
	}
	yaklog.Infof("Start SOCKS Server On [%s]", m.Host)

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   m.TargetTimeout,
			KeepAlive: m.TargetTimeout,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: false,
	}

	if m.Proxy != "" {
		proxyURL, err := url.Parse(m.Proxy)
		if err != nil {
			yaklog.Fatalf("Proxy URL is Invalid : %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	for {
		ctx := context.NewContext(tls.TLS_RSA_WITH_AES_128_CBC_SHA, m.DefaultSNI, transport)
		ctx.LogTamplate = fmt.Sprintf("[clientId:%s]", ctx.ContextId)

		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("%s Accept Client Connection Failed : %v", ctx.LogTamplate, err)
			continue
		}

		ctx.LogTamplate = fmt.Sprintf("%s [clientIP:%s] [%s]", ctx.LogTamplate, client.RemoteAddr().String(), colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
		reg := regexp.MustCompile(`:\d+$`)
		ctx.Client2MitmLog = fmt.Sprintf("[clientId:%s] [%s => %s]", ctx.ContextId, client.RemoteAddr().String(), reg.FindString(client.LocalAddr().String()))
		ctx.Mitm2ClientLog = fmt.Sprintf("[clientId:%s] [%s => %s]", ctx.ContextId, reg.FindString(client.LocalAddr().String()), client.RemoteAddr().String())

		yaklog.Infof("%s New Client Connection Successfully Established", ctx.LogTamplate)

		if setting.Config.Socks.Timeout.Switch {
			if err = client.SetDeadline(time.Now().Add(m.ClientTimeout)); err != nil {
				yaklog.Warnf("%s Set Client Deadline Failed : %v", ctx.LogTamplate, err)
			}
		}

		go Handler(client, ctx)
	}
}
