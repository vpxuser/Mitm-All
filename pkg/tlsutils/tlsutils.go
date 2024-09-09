package tlsutils

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"socks2https/pkg/ioutils"
)

const (
	TLS_FRAGMENT_MAX_SIZE = 16384
	TLS_RECORD_MAX_SIZE   = 65535
)

// ReadTLSRecord 解决TLS记录分片问题
func ReadTLSRecord(reader *bufio.Reader) ([]byte, error) {
	for offset, fragments := 0, make([]byte, 0); ; {
		// 读取TLS记录头部信息
		header, err := ioutils.ReadBytes(reader, 5)
		if err != nil {
			return nil, fmt.Errorf("read TLS Record Header failed : %v", err)
		}

		// 读取TLS有效载荷长度
		length := binary.BigEndian.Uint16(header[3:5])

		offset = offset + 5 + int(length)

		fragment, err := ioutils.ReadBytes(reader, int(length))
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read TLS Record Fragment failed : %v", err)
		}

		// 拼接有效载荷
		fragments = append(fragments, fragment...)

		if length < TLS_FRAGMENT_MAX_SIZE {
			if offset < TLS_FRAGMENT_MAX_SIZE {
				return append(header, fragment...), nil
			} else if offset >= TLS_FRAGMENT_MAX_SIZE && offset < TLS_RECORD_MAX_SIZE {
				fragmentsLength := make([]byte, 2)
				binary.BigEndian.PutUint16(fragmentsLength, uint16(offset))
				return append(header[:3], append(fragmentsLength, fragments...)...), nil
			} else {
				return append(header[:3], append([]byte{0xff, 0xff}, fragments...)...), nil
			}
		}
	}
}
