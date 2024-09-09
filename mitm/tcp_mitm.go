package mitm

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/setting"
	"sync"
)

func TCPMITM(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	defer conn.Close()
	addr := fmt.Sprintf("%s:%d", ctx.Host, ctx.Port)
	dst, err := net.DialTimeout("tcp", addr, setting.TargetTimeout)
	if err != nil {
		return fmt.Errorf("Connect to [%s] Failed : %v", addr, err)
	}
	defer dst.Close()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err = io.Copy(dst, reader); err != nil {
			yaklog.Warnf("Transfer Data to Target Failed : %v", err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		if _, err = io.Copy(conn, dst); err != nil {
			yaklog.Warnf("Transfer Data to Client Failed : %v", err)
			return
		}
	}()
	wg.Wait()
	return nil
}
