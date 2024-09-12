package connect

import (
	"bufio"
	"errors"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/context"
	"socks2https/setting"
	"sync"
	"time"
)

func Direct(reader *bufio.Reader, conn net.Conn, ctx *context.Context) {
	defer conn.Close()
	addr := fmt.Sprintf("%s:%d", ctx.Host, ctx.Port)
	dst, err := net.Dial("tcp", addr)
	if err != nil {
		yaklog.Errorf("%s New Target Connection Failed to Established  : %v", ctx.Mitm2TargetLog, err)
		return
	}
	defer dst.Close()
	yaklog.Infof("%s New Target Connection Successfully Established.", ctx.Mitm2TargetLog)
	if setting.Config.Socks.Timeout.Switch {
		if err = dst.SetDeadline(time.Now().Add(setting.Config.Socks.Timeout.Target)); err != nil {
			yaklog.Warnf("%s Failed to Set Target Connection Deadline : %v", ctx.Mitm2TargetLog, err)
		}
	}
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err = io.Copy(dst, reader); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				yaklog.Infof("%s Forward Data Finished.", ctx.Mitm2TargetLog)
			} else {
				yaklog.Warnf("%s Forward Data to Target Failed : %v", ctx.Mitm2TargetLog, err)
			}
			return
		}
		yaklog.Infof("%s Forward Data Finished.", ctx.Mitm2TargetLog)
	}()
	go func() {
		defer wg.Done()
		if _, err = io.Copy(conn, dst); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				yaklog.Infof("%s Forward Data Finished.", ctx.Target2MitmLog)
			} else {
				yaklog.Warnf("%s Forward Data to Client Failed : %v", ctx.Target2MitmLog, err)
			}
			return
		}
		yaklog.Infof("%s Forward Data Finished.", ctx.Target2MitmLog)
	}()
	wg.Wait()
}
