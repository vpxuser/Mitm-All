package tsocks

import (
	"bufio"
	"context"
	"github.com/yaklang/yaklang/common/cybertunnel/ctxio"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
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
	wCtx, cancel := context.WithCancel(context.Background())
	//ctxSrc := ctxio.NewReaderWriter(wCtx, client)
	ctxDst := ctxio.NewReaderWriter(wCtx, server)
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(ctxDst, readWriter); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Target failed: %v", tag, err)
		}
	}()
	go func() {
		defer func() {
			cancel()
			wg.Done()
		}()
		if _, err := io.Copy(readWriter, ctxDst); err != nil && err != io.EOF {
			yaklog.Errorf("%s write data to Client failed: %v", tag, err)
		}
	}()
	wg.Wait()
	return nil
}
