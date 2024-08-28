package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// EncryptPKCS1RSA PKCS1填充 RSA加密
func EncryptPKCS1RSA(pubKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 RSA Encrypt failed : %v", err)
	}
	return cipherText, nil
}

// DecryptPKCS1RSA PKCS1填充 RSA解密
func DecryptPKCS1RSA(privateKey *rsa.PrivateKey, chiperText []byte) ([]byte, error) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, chiperText)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 RSA Decrypt failed : %v", err)
	}
	return plainText, nil
}
