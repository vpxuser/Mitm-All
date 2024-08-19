package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"net/http"
	"net/url"
	"socks2https/pkg/comm"
	"socks2https/setting"
	"sync"
	"time"
)

func connect(client net.Conn, addr string) error {
	reader := bufio.NewReader(client)
	protocol, err := parseProtocol(reader)
	if err != nil {
		return err
	}
	switch protocol {
	case HTTP_PROTOCOL:
		return httpTunnel(reader, client)
	case HTTPS_PROTOCOL:
		//server, err := netx.DialTimeout(setting.TargetTimeout, addr, setting.Proxy)
		//if err != nil {
		//	return fmt.Errorf("%s create tcp connection failed: %v", tag, err)
		//}
		//return tcpTunnel(tag, readWriter, client, server)
		return httpsTunnel(addr, reader, client)
	default:
		server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
		if err != nil {
			return fmt.Errorf("%s create tcp connection failed: %v", err)
		}
		return tcpTunnel(reader, client, server)
	}
}

func readTLSRecord(reader *bufio.Reader, src, dst net.Conn) error {
	connection := fmt.Sprintf("%s ===> %s", src.RemoteAddr().String(), dst.RemoteAddr().String())
	for {
		recordHeader := make([]byte, 5)
		if _, err := reader.Read(recordHeader); err != nil && err != io.EOF {
			return fmt.Errorf("%s read TLS Record Header from Client failed : %v", connection, err)
		} else if _, err = dst.Write(recordHeader); err != nil {
			return fmt.Errorf("%s write TLS Record Header to Server failed : %v", connection, err)
		}
		contentType := recordHeader[0]
		handshakeSwitch := false
		if contentType == Handshake {
			handshakeSwitch = true
		}
		version := binary.BigEndian.Uint16(recordHeader[1:3])
		length := binary.BigEndian.Uint16(recordHeader[3:5])
		var protocol string
		if c, ok := ContentMap[contentType]; !ok {
			yaklog.Warnf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s Unknown TLS Record Content Type : %v", Tag, connection, &RecordHeader{ContentType: contentType, Version: version, Length: length})))
		} else if !handshakeSwitch {
			yaklog.Infof("%s %s Content Type : %s", Tag, connection, comm.SetColor(comm.YELLOW_COLOR_TYPE, c))
			if contentType == Alert {
				src.Close()
				//dst.Close()
				return fmt.Errorf("%s TLS Record Alert", connection)
			}
		} else {
			protocol = fmt.Sprintf("%s Content Type : %s ,", connection, comm.SetColor(comm.YELLOW_COLOR_TYPE, c))
		}
		recordPayload := make([]byte, length)
		if _, err := reader.Read(recordPayload); err != nil && err != io.EOF {
			return fmt.Errorf("%s read TLS Record Payload failed : %v", connection, err)
		} else if _, err = dst.Write(recordPayload); err != nil {
			return fmt.Errorf("%s write TLS Record Payload to Server failed : %v", connection, err)
		}
		if handshakeSwitch {
			handshakeType := recordPayload[0]

			if handshakeType == ClientHello {
				sni := parseSNI(parseClientHello(recordPayload[4:]).Extensions.Extension)
				yaklog.Debugf("%s %s", Tag, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, sni)))
			}

			if c, ok := HandshakeMap[handshakeType]; !ok {
				protocol = fmt.Sprintf("%s Handshake Type : %s", protocol, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished")))
				yaklog.Infof("%s %s", Tag, protocol)
			} else {
				protocol = fmt.Sprintf("%s Handshake Type : %s", protocol, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, c)))
				yaklog.Infof("%s %s", Tag, protocol)
			}
		}
	}
}

func httpsTunnel(addr string, clientReader *bufio.Reader, client net.Conn) error {
	defer client.Close()
	//proxy, err := url.Parse(setting.Proxy)
	//if err != nil {
	//	return fmt.Errorf("%s parse proxy url failed: %v", Tag, err)
	//}
	//server, err := net.DialTimeout(PROTOCOL_TCP, proxy.Host, setting.TargetTimeout)
	server, err := net.DialTimeout(PROTOCOL_TCP, addr, setting.TargetTimeout)
	if err != nil {
		return fmt.Errorf("connect to proxy server failed: %v", err)
	}
	defer server.Close()
	serverReader := bufio.NewReader(server)
	yaklog.Debugf("%s %s -> %s -> %s -> %s -> %s", Tag, client.RemoteAddr().String(), client.LocalAddr().String(), server.LocalAddr().String(), server.RemoteAddr().String(), addr)

	//connectReq := fmt.Sprintf("CONNECT %v HTTP/1.1\r\nHost: %v\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n", addr, addr)
	//yaklog.Debugf("%s http connect request: \n%s", Tag, comm.SetColor(comm.RED_COLOR_TYPE, connectReq))
	//if _, err = server.Write([]byte(connectReq)); err != nil {
	//	return fmt.Errorf("%s write HTTP CONNECT request to proxy server failed: %v", Tag, err)
	//}
	//resp, err := http.ReadResponse(serverReader, nil)
	//if err != nil {
	//	return fmt.Errorf("%s read HTTP CONNECT response from proxy server failed: %v", Tag, err)
	//}
	//comm.DumpResponse(resp, false, comm.BLUE_COLOR_TYPE)
	//if resp.StatusCode != http.StatusOK {
	//	return fmt.Errorf("%s proxy server reject connect with status code %d", Tag, resp.StatusCode)
	//}

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err = readTLSRecord(clientReader, client, server); err != nil {
			yaklog.Errorf("%s %v", Tag, err)
		}
	}()
	go func() {
		defer wg.Done()
		if err = readTLSRecord(serverReader, server, client); err != nil {
			yaklog.Errorf("%s %v", Tag, err)
		}
	}()
	wg.Wait()
	return nil
}

// 处理http连接
func httpTunnel(reader *bufio.Reader, conn net.Conn) error {
	defer conn.Close()
	// 从客户端连接中读取req对象
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("%s read HTTP request failed : %v", err)
	}
	// 解析代理服务器地址
	proxy, err := url.Parse(setting.Proxy)
	if err != nil {
		return fmt.Errorf("%s parse proxy url failed : %v", err)
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
		return fmt.Errorf("%s read HTTP response from proxy server failed : %v", err)
	}
	defer resp.Body.Close()
	// 将response对象写入到客户端连接
	if err = resp.Write(conn); err != nil {
		return fmt.Errorf("%s write HTTP response to Client failed : %v", err)
	}
	return nil
}

// 处理tcp和https连接
func tcpTunnel(reader *bufio.Reader, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(server, reader); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Target failed : %v", Tag, err)
			return
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, server); err != nil && err != io.EOF {
			yaklog.Warnf("%s transfer data to Client failed : %v", Tag, err)
			return
		}
	}()
	wg.Wait()
	return nil
}
