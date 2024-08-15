package socks

import (
	"bufio"
	"context"
	"fmt"
	"github.com/yaklang/yaklang/common/cybertunnel/ctxio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"github.com/yaklang/yaklang/common/netx"
	"io"
	"net"
	"net/http"
	"net/url"
	"socks2https/pkg/comm"
	"socks2https/setting"
	"strings"
	"sync"
	"time"
)

func forward(tag string, clientReader *bufio.Reader, client net.Conn, addr string) error {
	protocol, err := parseProtocol(tag, clientReader)
	if err != nil {
		return err
	}
	switch protocol {
	case HTTP_PROTOCOL:
		return httpTunnel(tag, clientReader, client)
	case HTTPS_PROTOCOL:
		server, err := netx.DialTimeout(setting.TargetTimeout, addr, setting.Proxy)
		if err != nil {
			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		}
		return tcpTunnel(tag, client, server)
	default:
		server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
		if err != nil {
			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		}
		return tcpTunnel(tag, client, server)
	}
}

func parseProtocol(tag string, reader *bufio.Reader) (int, error) {
	protocolHeader, err := reader.Peek(3)
	if err != nil {
		return TCP_PROTOCOL, fmt.Errorf("%s pre read ProtocolHeader failed : %v", tag, err)
	}
	if protocolHeader[0] == 0x16 {
		yaklog.Debugf("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "try to use TLS"))
		return HTTPS_PROTOCOL, nil
	}
	switch string(protocolHeader) {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "TRA", "CON":
		if string(protocolHeader) == "CON" {
			yaklog.Debugf("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "read CONNECT method , try to use TLS"))
		}
		yaklog.Debugf("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "try to use HTTP"))
		return HTTP_PROTOCOL, nil
	}
	return TCP_PROTOCOL, nil
}

func httpTunnel2(tag string, addr string, client net.Conn) error {
	yaklog.Debugf("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "use http tunnel V2"))
	proxyConn, err := net.Dial(PROTOCOL_TCP, "127.0.0.1:8081")
	if err != nil {
		return err
	}
	defer proxyConn.Close()
	// 发送 CONNECT 请求
	connectReq := "CONNECT " + strings.Split(addr, ":")[0] + " HTTP/1.1\r\nHost: " + strings.Split(addr, ":")[0] + "\r\n\r\n"
	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
	if err != nil {
		return err
	}
	comm.DumpResponse(resp)
	server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
	if err != nil {
		return err
	}
	return tcpTunnel(tag, client, server)
}

// 处理http连接
func httpTunnel(tag string, reader *bufio.Reader, conn net.Conn) error {
	// 从客户端连接中读取req对象
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("%s read HTTP request failed : %v", tag, err)
	}
	comm.DumpRequest(req)
	// 解析代理服务器地址
	proxy, err := url.Parse(setting.Proxy)
	if err != nil {
		return fmt.Errorf("%s parse proxy url failed : %v", tag, err)
	}
	// 创建代理服务器连接
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: false,
		},
	}
	// 设置代理请求，URL 需要显示完整路径，即 URL = SCHEMA + HOST + PATH（默认已设置）
	req.URL.Scheme = PROTOCOL_HTTP
	req.URL.Host = req.Host
	req.RequestURI = ""
	// 发送代理请求到代理服务器
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s revice HTTP response failed : %v", tag, err)
	}
	comm.DumpResponse(resp)
	// 将response对象写入到客户端连接
	if err = resp.Write(conn); err != nil && err != io.EOF {
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
		if _, err := io.Copy(ctxDst, ctxSrc); err != nil && err != io.EOF {
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
