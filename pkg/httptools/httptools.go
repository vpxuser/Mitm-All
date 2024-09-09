package httptools

import (
	"bufio"
	"fmt"
	"net/http"
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
