package socks

import (
	"bufio"
	"context"
	"fmt"
	"github.com/yaklang/yaklang/common/cybertunnel/ctxio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"net/http"
	"socks2https/setting"
	"sync"
)

func forward(protocol int, src, dst net.Conn) error {
	switch protocol {
	case HTTP_PROTOCOL:
		return httpTunnel(src, dst)
	default:
		return tcpTunnel(src, dst)
	}
}

// 处理tcp和https连接
func tcpTunnel(src, dst net.Conn) error {
	wg := new(sync.WaitGroup)
	wg.Add(2)
	wCtx, cancel := context.WithCancel(context.Background())
	ctxSrc := ctxio.NewReaderWriter(wCtx, src)
	ctxDst := ctxio.NewReaderWriter(wCtx, dst)
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxDst, ctxSrc); err != nil && err != io.EOF {
			yaklog.Errorf("forward [%s] to [%s] failed : %v", dst.RemoteAddr().String(), src.RemoteAddr().String(), err)
		}
	}()
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxSrc, ctxDst); err != nil && err != io.EOF {
			yaklog.Errorf("forward [%s] to [%s] failed : %v", src.RemoteAddr().String(), dst.RemoteAddr().String(), err)
		}
	}()
	wg.Wait()
	return nil
}

// 处理http连接
func httpTunnel(src, dst net.Conn) error {
	// 从客户端连接中读取req对象
	req, err := http.ReadRequest(bufio.NewReader(src))
	if err != nil {
		yaklog.Debugf("convert buffer to http request failed , try tcp tunnel")
		return tcpTunnel(src, dst)
	}
	// 将req对象写入到下游代理连接
	if err = req.Write(dst); err != nil && setting.Config.Socks.DebugSwitch && err != io.EOF {
		return err
	}
	// 从下游代理连接中读取resp对象
	resp, err := http.ReadResponse(bufio.NewReader(dst), req)
	if err != nil {
		return fmt.Errorf("convert buffer to http response failed")
	}
	// 将response对象写入到客户端连接
	if err = resp.Write(src); err != nil && setting.Config.Socks.DebugSwitch && err != io.EOF {
		return err
	}
	return nil
}
