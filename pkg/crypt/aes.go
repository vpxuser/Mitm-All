package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

//
//import (
//	"crypto/aes"
//	"fmt"
//)
//
//// AESEncrypt ECB/PKCS5/AES加密
//func AESEncrypt(key, text []byte) ([]byte, error) {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		return nil, fmt.Errorf("parse aesKey failed : %v", err)
//	}
//	// 填充明文
//	padText := PKCS5Pad(text, aes.BlockSize)
//	// 创建加密器
//	mode := NewECBEncrypter(block)
//	// 加密器明文
//	cipherText := make([]byte, len(padText))
//	if err = mode.CryptBlocks(cipherText, padText); err != nil {
//		return nil, fmt.Errorf("aes encrypt failed : %v", err)
//	}
//	return cipherText, nil
//}
//
//// AESDecrypt ECB/PKCS5/AESAES解密
//func AESDecrypt(key string, chiperText []byte) ([]byte, error) {
//	block, err := aes.NewCipher([]byte(key))
//	if err != nil {
//		return nil, fmt.Errorf("parse aesKey failed : %v", err)
//	}
//	// 创建解密器
//	mode := NewECBDecrypter(block)
//	plainText := make([]byte, len(chiperText))
//	// 解密密文
//	if err = mode.CryptBlocks(plainText, chiperText); err != nil {
//		return nil, fmt.Errorf("aes decrypt failed : %v", err)
//	}
//	unpadText, err := PKCS5Unpad(plainText, block.BlockSize())
//	if err != nil {
//		return nil, err
//	}
//	return unpadText, nil
//}

func DecryptAES128CBCPKCS7(chiperText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher : %v", err)
	}
	decryptor := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(chiperText))
	decryptor.CryptBlocks(plainText, chiperText)
	plainText = UnPadding(plainText)
	return plainText, nil
}
