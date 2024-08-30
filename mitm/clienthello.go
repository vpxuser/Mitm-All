package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	reader := bytes.NewReader(data)
	clientHello := &ClientHello{}
	if err := binary.Read(reader, binary.BigEndian, &clientHello.Version); err != nil {
		return nil, fmt.Errorf("parse ClientHello ClientHelloTLSVersion failed : %v", err)
	}
	if _, err := reader.Read(clientHello.Random[:]); err != nil {
		return nil, fmt.Errorf("parse ClientHello Random failed : %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &clientHello.SessionIDLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello SessionID Length failed : %v", err)
	}
	clientHello.SessionID = make([]byte, clientHello.SessionIDLength)
	if _, err := reader.Read(clientHello.SessionID); err != nil {
		return nil, fmt.Errorf("parse ClientHello SessionID failed : %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &clientHello.CipherSuitesLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello CipherSuites Length failed : %v", err)
	}
	clientHello.CipherSuites = make([]uint16, clientHello.CipherSuitesLength/2)
	if err := binary.Read(reader, binary.BigEndian, clientHello.CipherSuites); err != nil {
		return nil, fmt.Errorf("parse ClientHello CipherSuites failed : %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &clientHello.CompressionMethodsLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello CompressionMethods Length failed : %v", err)
	}
	clientHello.CompressionMethods = make([]uint8, clientHello.CompressionMethodsLength)
	if _, err := reader.Read(clientHello.CompressionMethods); err != nil {
		return nil, fmt.Errorf("parse ClientHello CompressionMethods failed : %v", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &clientHello.ExtensionsLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello Extensions Length failed : %v", err)
	}
	extensions := make([]byte, clientHello.ExtensionsLength)
	if _, err := reader.Read(extensions); err != nil {
		return nil, fmt.Errorf("parse ClientHello Extensions failed : %v", err)
	}
	for offset := uint16(0); offset < clientHello.ExtensionsLength; {
		extension, err := ParseExtension(extensions[offset:])
		if err != nil {
			return nil, err
		}
		clientHello.Extensions = append(clientHello.Extensions, *extension)
		offset += 2 + 2 + extension.Length
	}
	return clientHello, nil
}
