package comm

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

const PROTOCOL_HTTP = "http"

func SendProxiedReq(proxyUrl string, req *http.Request) (*http.Response, error) {
	// 解析代理服务器地址
	proxy, err := url.Parse(proxyUrl)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url failed : %v", err)
	}
	// 创建代理服务器连接
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: true,
		},
	}
	// 设置代理请求，URL 需要显示完整路径，即 URL = SCHEMA + HOST + PATH（默认已设置）
	req.URL.Scheme = PROTOCOL_HTTP
	req.URL.Host = req.Host
	req.RequestURI = ""
	// 发送代理请求到代理服务器
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("revice response failed : %v", err)
	}
	return resp, nil
}
