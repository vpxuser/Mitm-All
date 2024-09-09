package zip

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

func GzipDecompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read compress data failed : %v", err)
	}
	defer reader.Close()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress data failed : %v", err)
	}
	return decompressed, nil
}

func GzipCompress(data []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("gzip compress data failed : %v", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("gzip compress close failed : %v", err)
	}
	return compressed.Bytes(), nil
}
