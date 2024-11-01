package porxy

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
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

type MITMServer struct {
	Host          string
	Threads       int
	ClientTimeout time.Duration
	TargetTimeout time.Duration
}

func NewMITMServer() *MITMServer {
	return &MITMServer{
		Host:          "0.0.0.0:1080",
		Threads:       0,
		ClientTimeout: time.Second * 30,
		TargetTimeout: time.Second * 30,
	}
}

func (m *MITMServer) Run() {
	server, err := net.Listen(PROTOCOL_TCP, m.Host)
	if err != nil {
		yaklog.Fatalf("Start SOCKS Server Failed : %v", err)
	}
	yaklog.Infof("Start SOCKS Server On [%s]", m.Host)

	var threads chan struct{}
	if m.Threads > 0 {
		threads = make(chan struct{}, m.Threads)
	}

	for {
		ctx := context.NewContext()
		ctx.LogTamplate = fmt.Sprintf("[contextId:%s]", ctx.ContextId)

		client, err := server.Accept()
		if err != nil {
			yaklog.Errorf("%s Accept Client Connection Failed : %v", ctx.LogTamplate, err)
			continue
		}

		ctx.LogTamplate = fmt.Sprintf("%s [clientIp:%s] [%s]", ctx.LogTamplate, client.RemoteAddr().String(), colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
		reg := regexp.MustCompile(`:\d+$`)
		ctx.Client2MitmLog = fmt.Sprintf("[contextId:%s] [%s => %s]", ctx.ContextId, client.RemoteAddr().String(), reg.FindString(client.LocalAddr().String()))
		ctx.Mitm2ClientLog = fmt.Sprintf("[contextId:%s] [%s => %s]", ctx.ContextId, reg.FindString(client.LocalAddr().String()), client.RemoteAddr().String())

		yaklog.Infof("%s New Client Connection Successfully Established", ctx.LogTamplate)

		if setting.Config.MITM.Timeout.Switch {
			if err = client.SetDeadline(time.Now().Add(m.ClientTimeout)); err != nil {
				yaklog.Warnf("%s Set Client Deadline Failed : %v", ctx.LogTamplate, err)
			}
		}

		reader := bufio.NewReader(client)
		if m.Threads > 0 {
			threads <- struct{}{}
			go func(client net.Conn, ctx *context.Context) {
				defer func() { <-threads }()
				Handler(reader, client, ctx)
			}(client, ctx)
		} else {
			go Handler(reader, client, ctx)
		}
	}
}
