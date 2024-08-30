package crypt

import (
	"bytes"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
)

func Pad(cipherText []byte, blockSize int) []byte {
	paddingLen := blockSize - len(cipherText)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(cipherText, paddingText...)
}

func UnPad(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	if length == 0 || length%blockSize != 0 {
		return nil, fmt.Errorf("invalid padding size : length = %d , blockSize = %d", length, blockSize)
	}
	paddingLen := int(plainText[length-1])
	yaklog.Debugf("Padding length : %d", paddingLen)
	if paddingLen < 1 || paddingLen > blockSize || paddingLen > length {
		return nil, fmt.Errorf("invalid padding length : paddingLen = %d , blockSize = %d", paddingLen, blockSize)
	}
	for i := length - paddingLen; i < length; i++ {
		if int(plainText[i]) != paddingLen {
			return nil, fmt.Errorf("invalid padding value at index %d : expected %d , got %d", i, paddingLen, plainText[i])
		}
	}
	return plainText[:(length - paddingLen)], nil
}
