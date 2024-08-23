package mitm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"socks2https/pkg/comm"
	"socks2https/pkg/protocol"
	"strings"
)

func HeadProtocol(conn net.Conn, addr string) error {
	Tag := fmt.Sprintf("[%s]", conn.RemoteAddr().String())
	reader := bufio.NewReader(conn)
	header, err := reader.Peek(7)
	if err != nil {
		return fmt.Errorf("read Protocol Header failed : %v", err)
	}
	maybeTLS := false
	if _, ok := protocol.ContentType[header[0]]; ok {
		maybeTLS = true
	} else if httpMethod, ok := HttpMethod[strings.TrimSpace(string(header))]; ok {
		if httpMethod == http.MethodConnect {
			yaklog.Infof("%s %s", Tag, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "use HTTP CONNECT Connection")))
		}
		yaklog.Infof("%s %s", Tag, comm.SetColor(comm.RED_COLOR_TYPE, "use HTTP Connection"))
		return HTTPMITM(reader, conn)
	}
	if maybeTLS {
		version := binary.BigEndian.Uint16(header[1:3])
		if version >= protocol.VersionSSL30 && version <= protocol.VersionTLS13 {
			yaklog.Infof("%s %s", Tag, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, "use TSL Connection")))
			return TLSMITM(reader, conn, addr)
		}
	}
	yaklog.Infof("%s Client use TCP connection", Tag)
	return TCPMITM(reader, conn, addr)
}
