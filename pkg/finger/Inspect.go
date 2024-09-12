package finger

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"socks2https/pkg/tlsutils"
	"strings"
)

const (
	TCP   = "TCP"
	SOCKS = "SOCKS"
	TLS   = "TLS"
	HTTP  = "HTTP"
)

var (
	SOCKSFingers = []byte{0x05, 0x00}
	HTTPFingers  = []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
		"HTTP/",
	}
)

func Inspect(reader *bufio.Reader) string {
	peek, err := reader.Peek(7)
	if err != nil {
		return TCP
	}
	if bytes.Equal(peek[:2], SOCKSFingers) {
		return SOCKS
	}
	version := binary.BigEndian.Uint16(peek[1:3])
	if _, ok := tlsutils.ContentType[peek[0]]; ok && version >= tls.VersionSSL30 && version <= tls.VersionTLS13 {
		return TLS
	}
	for _, finger := range HTTPFingers {
		if strings.Contains(string(peek), finger) {
			return HTTP
		}
	}
	return TCP
}
