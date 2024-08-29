package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// EncryptRSAPKCS PKCS1填充 RSA加密
func EncryptRSAPKCS(pubKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 RSA Encrypt failed : %v", err)
	}
	return cipherText, nil
}

// DecryptRSAPKCS PKCS1填充 RSA解密
func DecryptRSAPKCS(privateKey *rsa.PrivateKey, chiperText []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, chiperText)
}
