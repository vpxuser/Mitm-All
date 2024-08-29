package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
)

func EncryptAESCBC(plainText []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("parse Key failed: %v", err)
	}
	paddedText := Pad(plainText, block.BlockSize())
	cipherText := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedText)
	return cipherText, nil
}

func DecryptAESCBC(cipherText []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("parse Key failed : %v", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("invalid IV length: expected %d, got %d", block.BlockSize(), len(iv))
	}
	if len(cipherText)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: not a multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Padded Alert Length : %d , Padded ALert : %v", len(plainText), plainText)))
	unPadText, err := UnPad(plainText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return unPadText, nil
}
