package crypt

import (
	"crypto/cipher"
	"errors"
)

// ECB分块对象
type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb

// NewECBEncrypter 创建AES ECB模式加密器
func NewECBEncrypter(b cipher.Block) *ecbEncrypter {
	return &ecbEncrypter{b, b.BlockSize()}
}

// CryptBlocks 加密数据块
func (e *ecbEncrypter) CryptBlocks(dst, src []byte) error {
	if len(src)%e.blockSize != 0 || len(dst) < len(src) {
		return errors.New("ecbEncrypter: input not full blocks")
	}
	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
	return nil
}

type ecbDecrypter ecb

// NewECBDecrypter 创建AES ECB模式解密器
func NewECBDecrypter(b cipher.Block) *ecbDecrypter {
	return &ecbDecrypter{b, b.BlockSize()}
}

// CryptBlocks 解密数据块
func (e *ecbDecrypter) CryptBlocks(dst, src []byte) error {
	if len(src)%e.blockSize != 0 || len(dst) < len(src) {
		return errors.New("ecbEncrypter: input not full blocks")
	}
	for len(src) > 0 {
		e.b.Decrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
	return nil
}
