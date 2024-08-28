package crypt

import "fmt"

func Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("padding invalid")
	}
	paddingLen := int(data[length-1])
	if paddingLen == 0 || paddingLen > blockSize {
		return nil, fmt.Errorf("padding size invalid")
	}
	return data[:length-paddingLen], nil
}
