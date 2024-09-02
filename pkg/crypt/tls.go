package crypt

import (
	"crypto/hmac"
	"hash"
)

func Label(label string) []byte {
	return []byte(label)
}

func HmacHash(secret, A []byte, hashFunc func() hash.Hash) []byte {
	hmacFunc := hmac.New(hashFunc, secret)
	hmacFunc.Write(A)
	return hmacFunc.Sum(nil)
}

func PHash(secret, seed []byte, outputLength int, hashFunc func() hash.Hash) []byte {
	var result []byte
	A := seed
	for len(result) < outputLength {
		A = HmacHash(secret, A, hashFunc)
		result = append(result, HmacHash(secret, append(A, seed...), hashFunc)...)
	}
	return result
}

func XOR(pMD5, pSHA1 []byte) []byte {
	var result []byte
	for i := 0; i < len(pMD5); i++ {
		result = append(result, pMD5[i]^pSHA1[i])
	}
	return result
}
