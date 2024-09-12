package httphandler

import (
	"bytes"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net/http"
	"socks2https/context"
	"socks2https/pkg/zip"
)

var GzipDecompressResponse = ResponseHandler(func(resp *http.Response, ctx *context.Context) *http.Response {
	if resp.Header.Get("Content-Encoding") == "gzip" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			yaklog.Warnf("read gzip body failed : %v", err)
			return resp
		}
		decompressedBody, err := zip.GzipDecompress(body)
		if err != nil {
			yaklog.Warnf("gzip decompress body failed : %v", err)
			return resp
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(decompressedBody))
		resp.ContentLength = int64(len(decompressedBody))
		//colorutils.DumpResponse(resp, true, colorutils.RED_COLOR_TYPE)
		//resp.ContentLength = int64(len(body))
		//resp.Body = io.NopCloser(bytes.NewBuffer(body))
	}
	return resp
})

var GzipCompressResponse = ResponseHandler(func(resp *http.Response, ctx *context.Context) *http.Response {
	if resp.Header.Get("Content-Encoding") == "gzip" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			yaklog.Warnf("read gzip body failed : %v", err)
			return resp
		}
		compressedBody, err := zip.GzipCompress(body)
		if err != nil {
			yaklog.Warnf("gzip compress body failed : %v", err)
			return resp
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(compressedBody))
		resp.ContentLength = int64(len(compressedBody))
	}
	return resp
})
