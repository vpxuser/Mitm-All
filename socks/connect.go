package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"net/http"
	"socks2https/mitm"
	"socks2https/pkg/comm"
	"strings"
)

func Connect(conn net.Conn, ctx *mitm.Context) error {
	// 创建一个缓冲区，缓冲区默认1GB
	reader := bufio.NewReaderSize(conn, ctx.BufferSize)
	header, err := reader.Peek(7)
	if err != nil {
		return fmt.Errorf("read Protocol Header failed : %v", err)
	}
	maybeTLS := false
	if _, ok := mitm.ContentType[header[0]]; ok {
		maybeTLS = true
	} else if httpMethod, ok := mitm.HttpMethod[strings.TrimSpace(string(header))]; ok {
		if httpMethod == http.MethodConnect {
			yaklog.Infof("%s %s", ctx.LogTamplate, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "use HTTP CONNECT Connection")))
		}
		yaklog.Infof("%s %s", ctx.LogTamplate, comm.SetColor(comm.RED_COLOR_TYPE, "use HTTP Connection"))
		return mitm.HTTPMITM(reader, conn)
	}
	if maybeTLS {
		version := binary.BigEndian.Uint16(header[1:3])
		if version >= mitm.VersionSSL300 && version <= mitm.VersionTLS103 {
			yaklog.Infof("%s %s", ctx.LogTamplate, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, "use TSL Connection")))
			mitm.TLSMITM(reader, conn, ctx)
			return nil
		}
	}
	yaklog.Infof("%s Client use TCP connection", ctx.LogTamplate)
	return mitm.TCPMITM(reader, conn, ctx)
}
