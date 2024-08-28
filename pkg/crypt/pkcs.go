package crypt

import (
	"bytes"
	"fmt"
)

func Pad(plainText []byte, blockSize int) []byte {
	paddingLen := blockSize - len(plainText)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(plainText, paddingText...)
}

func UnPad(cipherText []byte, blockSize int) ([]byte, error) {
	length := len(cipherText)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	paddingLen := int(cipherText[length-1])
	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length")
	}
	for _, b := range cipherText[length-paddingLen:] {
		if int(b) != paddingLen {
			return nil, fmt.Errorf("invalid padding value")
		}
	}
	return cipherText[:length-paddingLen], nil
}
