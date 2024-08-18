package socks

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"socks2https/pkg/comm"
	"socks2https/setting"
	"sync"
	"time"
)

func connect(tag string, readWriter *bufio.ReadWriter, client net.Conn, addr string) error {
	protocol, err := parseProtocol(tag, readWriter)
	if err != nil {
		return err
	}
	switch protocol {
	case HTTP_PROTOCOL:
		return httpTunnel(tag, readWriter, client)
	case HTTPS_PROTOCOL:
		//server, err := netx.DialTimeout(setting.TargetTimeout, addr, setting.Proxy)
		//if err != nil {
		//	return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		//}
		//return tcpTunnel(tag, readWriter, client, server)
		return httpsTunnel(tag, addr, readWriter, client)
	default:
		server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
		if err != nil {
			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		}
		return tcpTunnel(tag, readWriter, client, server)
	}
}

func httpsTunnel(tag, addr string, readWriter *bufio.ReadWriter, client net.Conn) error {
	defer client.Close()
	proxy, err := url.Parse(setting.Proxy)
	if err != nil {
		return fmt.Errorf("%s parse proxy url failed: %v", tag, err)
	}
	server, err := net.DialTimeout(PROTOCOL_TCP, proxy.Host, setting.TargetTimeout)
	if err != nil {
		return fmt.Errorf("%s connect to proxy server failed: %v", tag, err)
	}
	defer server.Close()
	yaklog.Debugf("%s %s -> %s -> %s -> %s -> %s", tag, client.RemoteAddr().String(), client.LocalAddr().String(), server.LocalAddr().String(), server.RemoteAddr().String(), addr)
	connectReq := fmt.Sprintf("CONNECT %v HTTP/1.1\r\nHost: %v\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n", addr, addr)
	yaklog.Debugf("%s http connect request: \n%s", tag, comm.SetColor(comm.RED_COLOR_TYPE, connectReq))
	if _, err = server.Write([]byte(connectReq)); err != nil {
		return fmt.Errorf("%s write HTTP CONNECT request to proxy server failed: %v", tag, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(server), nil)
	if err != nil {
		return fmt.Errorf("%s read HTTP CONNECT response from proxy server failed: %v", tag, err)
	}
	connectResp, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return fmt.Errorf("%s dump HTTP CONNECT response failed: %v", tag, err)
	}
	yaklog.Debugf("%s http connect response: \n%s", tag, comm.SetColor(comm.RED_COLOR_TYPE, string(connectResp)))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s proxy server reject connect with status code %d", tag, resp.StatusCode)
	}
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err = readWriter.WriteTo(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Target failed : %v", tag, err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		if _, err = readWriter.ReadFrom(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Client failed : %v", tag, err)
			return
		}
	}()
	wg.Wait()
	return nil
}

func parseProtocol(tag string, readWriter *bufio.ReadWriter) (int, error) {
	protocolHeader, err := readWriter.Peek(3)
	if err != nil {
		return TCP_PROTOCOL, fmt.Errorf("%s pre read Protocol Header failed : %v", tag, err)
	}
	if string(protocolHeader) == "CON" {
		connectReq, _ := readWriter.Peek(50)
		yaklog.Debugf("%s connect request header: %s", tag, string(connectReq))
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Client use CONNECT connection")))
		return HTTPS_PROTOCOL, nil
	} else if protocolHeader[0] == 0x16 {
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, "Client use TSL connection")))
		return HTTPS_PROTOCOL, nil
	}
	switch string(protocolHeader) {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "TRA":
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "Client use HTTP connection"))
		return HTTP_PROTOCOL, nil
	}
	yaklog.Infof("%s Client use TCP connection", tag)
	return TCP_PROTOCOL, nil
}

// 处理http连接
func httpTunnel(tag string, readWriter *bufio.ReadWriter, conn net.Conn) error {
	defer conn.Close()
	// 从客户端连接中读取req对象
	req, err := http.ReadRequest(readWriter.Reader)
	if err != nil {
		return fmt.Errorf("%s read HTTP request failed : %v", tag, err)
	}
	//comm.DumpRequest(req)
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
	//comm.DumpResponse(resp)
	// 将response对象写入到客户端连接
	buf, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return fmt.Errorf("%s dump response failed : %v", tag, err)
	} else if _, err = readWriter.Write(buf); err != nil {
		return fmt.Errorf("%s write response to Client failed : %v", tag, err)
	} else if err = readWriter.Flush(); err != nil {
		return fmt.Errorf("%s flush response failed : %v", tag, err)
	}
	return nil
}

// 处理tcp和https连接
func tcpTunnel(tag string, readWriter *bufio.ReadWriter, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := readWriter.WriteTo(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Target failed : %v", tag, err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := readWriter.ReadFrom(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Client failed : %v", tag, err)
			return
		}
	}()
	wg.Wait()
	return nil
}
