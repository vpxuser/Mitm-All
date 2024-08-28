package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func DecryptAESCBC(chiperText []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("parse aesKey failed : %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(chiperText))
	mode.CryptBlocks(plainText, chiperText)
	unpadText, err := Unpad(plainText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return unpadText, nil
}
