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
		return nil, fmt.Errorf("invalid padding size : length = %d , blockSize = %d", length, blockSize)
	}
	paddingLen := int(cipherText[length-1])
	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length : paddingLen = %d , blockSize = %d", paddingLen, blockSize)
	}
	for i := length - paddingLen; i < length; i++ {
		if int(cipherText[i]) != paddingLen {
			return nil, fmt.Errorf("invalid padding value at index %d : expected %d , got %d", i, paddingLen, cipherText[i])
		}
	}
	return cipherText[:length-paddingLen], nil
}
