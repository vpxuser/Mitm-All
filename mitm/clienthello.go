package mitm

import (
	"encoding/binary"
)

type ClientHello struct {
	Version                  uint16      `json:"clientHelloTLSVersion"`
	Random                   [32]byte    `json:"random"`
	SessionIDLength          uint8       `json:"sessionIDLength"`
	SessionID                []byte      `json:"sessionID"`
	CipherSuitesLength       uint16      `json:"cipherSuitesLength"`
	CipherSuites             []uint16    `json:"cipherSuites"`
	CompressionMethodsLength uint8       `json:"compressionMethodsLength"`
	CompressionMethods       []uint8     `json:"compressionMethods"`
	ExtensionsLength         uint16      `json:"extensionsLength"`
	Extensions               []Extension `json:"extensions,omitempty"`
}

// ParseClientHello 解析Clienthello函数
func ParseClientHello(data []byte) (*ClientHello, error) {
	clientHello := &ClientHello{
		Version:         binary.BigEndian.Uint16(data[0:2]),
		Random:          [32]byte(data[2:34]),
		SessionIDLength: data[34],
	}
	offset := 35
	clientHello.SessionID = data[offset : offset+int(clientHello.SessionIDLength)]
	offset += int(clientHello.SessionIDLength)
	clientHello.CipherSuitesLength = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	for i := 0; i < int(clientHello.CipherSuitesLength/2); i++ {
		clientHello.CipherSuites = append(clientHello.CipherSuites, binary.BigEndian.Uint16(data[offset:offset+2]))
		offset += 2
	}
	clientHello.CompressionMethodsLength = data[offset]
	offset += 1
	for i := 0; i < int(clientHello.CompressionMethodsLength); i++ {
		clientHello.CompressionMethods = append(clientHello.CompressionMethods, data[offset])
		offset += 1
	}
	clientHello.ExtensionsLength = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	extensions := data[offset : offset+int(clientHello.ExtensionsLength)]
	for i := 0; i < int(clientHello.ExtensionsLength); {
		extension, err := ParseExtension(extensions[i:])
		if err != nil {
			return nil, err
		}
		clientHello.Extensions = append(clientHello.Extensions, *extension)
		i += 2 + 2 + int(extension.Length)
	}
	return clientHello, nil
}
