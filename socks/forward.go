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
	"socks2https/pkg/comm"
	"socks2https/setting"
	"sync"
)

func forward(tag string, protocol int, client, server net.Conn) error {
	switch protocol {
	case HTTP_PROTOCOL:
		return httpTunnel(tag, client, server)
	case HTTPS_PROTOCOL:
		//return httpsTunnel(src, dst)
		return tcpTunnel(tag, client, server)
	default:
		return tcpTunnel(tag, client, server)
	}
}

// 处理http连接
func httpTunnel(tag string, client, server net.Conn) error {
	_ = server.Close()
	// 从客户端连接中读取req对象
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		return fmt.Errorf("%s read HTTP request failed : %v", tag, err)
	}
	comm.DumpRequest(req)
	resp, err := comm.SendProxiedReq(setting.Proxy, req)
	if err != nil {
		return fmt.Errorf("%s %v", tag, err)
	}
	comm.DumpResponse(resp)
	// 将response对象写入到客户端连接
	if err = resp.Write(client); err != nil && err != io.EOF {
		return fmt.Errorf("%s send response to Client failed : %v", tag, err)
	}
	return nil
}

// 处理tcp和https连接
func tcpTunnel(tag string, client, server net.Conn) error {
	wg := new(sync.WaitGroup)
	wg.Add(2)
	wCtx, cancel := context.WithCancel(context.Background())
	ctxSrc := ctxio.NewReaderWriter(wCtx, client)
	ctxDst := ctxio.NewReaderWriter(wCtx, server)
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxDst, ctxSrc); err != nil || err != io.EOF {
			yaklog.Errorf("%s forward data to Target failed : %v", tag, err)
		}
	}()
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxSrc, ctxDst); err != nil && err != io.EOF {
			yaklog.Errorf("%s forward data to Client failed : %v", tag, err)
		}
	}()
	wg.Wait()
	return nil
}
