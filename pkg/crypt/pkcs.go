package crypt

// UnPadding PKCS7
func UnPadding(data []byte) []byte {
	length := len(data)
	padLen := int(data[length-1])
	return data[:length-padLen]
}
