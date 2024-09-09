package ioutils

import (
	"bufio"
	"fmt"
)

func ReadBytes(reader *bufio.Reader, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be greater than 0")
	}
	buf := make([]byte, length)
	for offset := 0; offset < length; {
		n, err := reader.Read(buf[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
	}
	return buf, nil
}
