package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// PKCS1RSAEncrypt PKCS1填充 RSA加密
func PKCS1RSAEncrypt(pubKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 RSA Encrypt failed : %v", err)
	}
	return cipherText, nil
}

// PKCS1RSADecrypt PKCS1填充 RSA解密
func PKCS1RSADecrypt(privateKey *rsa.PrivateKey, chiperText []byte) ([]byte, error) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, chiperText)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 RSA Decrypt failed : %v", err)
	}
	return plainText, nil
}
