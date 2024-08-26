package socks

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"socks2https/pkg/comm"
	"socks2https/setting"
)

var HttpMethod = map[string]string{
	http.MethodGet:     http.MethodGet,
	http.MethodHead:    http.MethodHead,
	http.MethodPost:    http.MethodPost,
	http.MethodPut:     http.MethodPut,
	http.MethodPatch:   http.MethodPatch,
	http.MethodDelete:  http.MethodDelete,
	http.MethodConnect: http.MethodConnect,
	http.MethodOptions: http.MethodOptions,
	http.MethodTrace:   http.MethodTrace,
}

func HTTPMITM(reader *bufio.Reader, conn net.Conn) error {
	Tag := fmt.Sprintf("[%s]", conn.RemoteAddr().String())
	defer conn.Close()
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("%s read HTTP Request failed : %v", Tag, err)
	}
	comm.DumpRequest(req, true, comm.RED_COLOR_TYPE)
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   setting.TargetTimeout,
				KeepAlive: setting.TargetTimeout,
			}).DialContext,
			ForceAttemptHTTP2: false,
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s read HTTP Response from Target failed : %v", Tag, err)
	}
	defer resp.Body.Close()
	comm.DumpResponse(resp, true, comm.RED_COLOR_TYPE)
	if err = resp.Write(conn); err != nil {
		return fmt.Errorf("%s write HTTP Response to Client failed : %v", Tag, err)
	}
	return nil
}
