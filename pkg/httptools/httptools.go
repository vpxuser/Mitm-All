package httptools

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func ReadRequest(reader *bufio.Reader, scheme string) (*http.Request, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("Read Request Failed : %v", err)
	}
	req.URL.Scheme = scheme
	req.URL.Host = req.Host
	req.RequestURI = ""
	return req, nil
}

func NewConnectResponse() *http.Response {
	return &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusOK,
		Status:     "Connection Established",
	}
}

func ParseHostAndPort(addr string) (string, uint16, error) {
	str := strings.Split(addr, ":")
	port, err := strconv.ParseUint(str[1], 10, 16)
	if err != nil {
		return str[0], 0, fmt.Errorf("Failed to Parse Port From Address : %v", err)
	}
	return str[0], uint16(port), nil
}
