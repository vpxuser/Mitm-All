package socks

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
		return fmt.Errorf("connect to [%s] failed : %v", addr, err)
	}
	defer dst.Close()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err = io.Copy(dst, reader); err != nil && err != io.EOF {
			yaklog.Warnf("transfer data to Target failed : %v", err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		if _, err = io.Copy(conn, dst); err != nil && err != io.EOF {
			yaklog.Warnf("transfer data to Client failed : %v", err)
			return
		}
	}()
	wg.Wait()
	return nil
}
