package tsocks

import (
	"bufio"
	"context"
	"fmt"
	"github.com/yaklang/yaklang/common/cybertunnel/ctxio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/pkg/comm"
	"sync"
)

// 处理tcp和https连接
func forward(tag string, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	wCtx, cancel := context.WithCancel(context.Background())
	ctxSrc := ctxio.NewReaderWriter(wCtx, client)
	ctxDst := ctxio.NewReaderWriter(wCtx, server)
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxDst, ctxSrc); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Target failed: %v", tag, err)
		}
	}()
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxSrc, ctxDst); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Client failed: %v", tag, err)
		}
	}()
	wg.Wait()
	return nil
}

func forwardReader(tag string, reader *bufio.Reader, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	wCtx, cancel := context.WithCancel(context.Background())
	ctxSrc := ctxio.NewReaderWriter(wCtx, client)
	ctxDst := ctxio.NewReaderWriter(wCtx, server)
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxDst, reader); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Target failed: %v", tag, err)
		}
	}()
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxSrc, ctxDst); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Client failed: %v", tag, err)
		}
	}()
	wg.Wait()
	return nil
}

func forwardReadWriter(tag string, readWriter *bufio.ReadWriter, client, server net.Conn) error {
	defer func() {
		server.Close()
		client.Close()
	}()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := readWriter.WriteTo(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s write data to Target failed: %v", tag, err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := readWriter.ReadFrom(server); err != nil && err != io.EOF {
			yaklog.Warnf("%s write data to Client failed: %v", tag, err)
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
	if protocolHeader[0] == 0x16 {
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, "Client use TSL connection")))
		return HTTPS_PROTOCOL, nil
	}
	switch string(protocolHeader) {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "TRA", "CON":
		yaklog.Infof("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, "Client use HTTP connection"))
		return HTTP_PROTOCOL, nil
	default:
		yaklog.Infof("%s Client use TCP connection", tag)
		return TCP_PROTOCOL, nil
	}
}
