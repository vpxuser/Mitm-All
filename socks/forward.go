package socks

import (
	"bufio"
	"context"
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
		return httpTunnel(tag, readWriter)
	case HTTPS_PROTOCOL:
		//server, err := netx.DialTimeout(setting.TargetTimeout, addr, setting.Proxy)
		//server, err := net.DialTimeout(PROTOCOL_TCP, "127.0.0.1:8081", setting.TargetTimeout)
		//if err != nil {
		//	return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		//}
		//return tcpTunnel(tag, readWriter, client, server)
		return httpConnectTunnel(tag, addr, readWriter, client)
	default:
		server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
		if err != nil {
			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		}
		return tcpTunnel(tag, readWriter, client, server)
		//return tcpTunnel(tag, client, server)
	}
}

//func forward(tag string, clientReader *bufio.Reader, client net.Conn, addr string) error {
//	protocol, err := parseProtocol(tag, clientReader)
//	if err != nil {
//		return err
//	}
//	switch protocol {
//	case HTTP_PROTOCOL:
//		return httpTunnel(tag, clientReader, client)
//	case HTTPS_PROTOCOL:
//		server, err := netx.DialTimeout(setting.TargetTimeout, addr, setting.Proxy)
//		if err != nil {
//			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
//		}
//		return tcpTunnel(tag, clientReader, client, server)
//	default:
//		server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
//		if err != nil {
//			return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
//		}
//		return tcpTunnel(tag, clientReader, client, server)
//	}
//}

func parseProtocol(tag string, readWriter *bufio.ReadWriter) (int, error) {
	protocolHeader, err := readWriter.Peek(3)
	if err != nil {
		return TCP_PROTOCOL, fmt.Errorf("%s pre read Protocol Header failed : %v", tag, err)
	}
	if protocolHeader[0] == 0x16 {
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, "Client use TSL connection")))
		return HTTPS_PROTOCOL, nil
	}
	switch string(protocolHeader) {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "TRA", "CON":
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "Client use HTTP connection"))
		return HTTP_PROTOCOL, nil
	}
	yaklog.Infof("%s Client use TCP connection", tag)
	return TCP_PROTOCOL, nil
}

// 处理http连接
func httpTunnel(tag string, readWriter *bufio.ReadWriter) error {
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

func httpConnectTunnel(tag string, addr string, readWriter *bufio.ReadWriter, client net.Conn) error {
	proxyURL, err := url.Parse(setting.Proxy)
	if err != nil {
		return fmt.Errorf("%s parse HTTP proxy url failed : %v", tag, err)
	}
	// 创建 TCP 连接到代理服务器
	proxyConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		return fmt.Errorf("%s connect to proxy failed : %v", tag, err)
	}
	//return tcpTunnel(tag, client, proxyConn)
	return tcpTunnel(tag, readWriter, client, proxyConn)
	payload := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", http.MethodConnect, addr, addr)
	yaklog.Debugf("\n%s", comm.SetColor(comm.BLUE_COLOR_TYPE, payload))
	if _, err = proxyConn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("%s write HTTP CONNECT request to proxy server failed : %v", tag, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
	if err != nil {
		return fmt.Errorf("%s read HTTP CONNECT response from proxy server failed : %v", tag, err)
	}
	defer resp.Body.Close()
	// 确保连接成功
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s connect to proxy server failed witch Status Code : %v", tag, resp.Status)
	}
	comm.DumpResponse(resp)
	yaklog.Infof("%s connect to proxy server success", tag)
	// 从代理服务器获取连接
	//return tcpTunnel(tag, readWriter, client, proxyConn)
	ctx, cancel := context.WithCancel(context.Background()) //启动一个可以取消的上下文功能
	defer cancel()
	go func() {
		if _, err = readWriter.WriteTo(proxyConn); err != nil {
			yaklog.Errorf("%s write HTTPS request to proxy server failed : %v", tag, err)
		}
		cancel()
	}()
	go func() {
		if _, err = readWriter.ReadFrom(proxyConn); err != nil {
			yaklog.Errorf("%s read HTTPS request from proxy server failed : %v", tag, err)
		}
		cancel()
	}()
	<-ctx.Done() // 这里是 只要管道输出内容了就停止 所以上面两个协程 只要有一个输出 就取消
	return nil
}

//func tcpTunnel(tag string, client, server net.Conn) error {
//	wg := new(sync.WaitGroup)
//	wg.Add(2)
//	wCtx, cancel := context.WithCancel(context.Background())
//	ctxSrc := ctxio.NewReaderWriter(wCtx, client)
//	ctxDst := ctxio.NewReaderWriter(wCtx, server)
//	go func() {
//		defer func() {
//			cancel()
//			wg.Done()
//		}()
//		if _, err := io.Copy(ctxDst, ctxSrc); err != nil && err != io.EOF {
//			yaklog.Errorf("%s forward data to Target failed : %v", tag, err)
//		}
//	}()
//	go func() {
//		defer func() {
//			cancel()
//			wg.Done()
//		}()
//		if _, err := io.Copy(ctxSrc, ctxDst); err != nil && err != io.EOF {
//			yaklog.Errorf("%s forward data to Client failed : %v", tag, err)
//		}
//	}()
//	wg.Wait()
//	return nil
//}

// 处理tcp和https连接
func tcpTunnel(tag string, readWriter *bufio.ReadWriter, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer func() {
			cancel()
			//wg.Done()
		}()
		if _, err := readWriter.WriteTo(server); err != nil && err != io.EOF {
			yaklog.Errorf("%s transfer data to Target failed : %v", tag, err)
			return
		}
	}()
	go func() {
		defer func() {
			cancel()
			//wg.Done()
		}()
		if _, err := readWriter.ReadFrom(server); err != nil && err != io.EOF {
			yaklog.Errorf("%s transfer data to Client failed : %v", tag, err)
			return
		}
	}()
	//wg.Wait()
	<-ctx.Done()
	cancel()
	return nil
}
