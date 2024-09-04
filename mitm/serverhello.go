package mitm

import (
	"encoding/binary"
)

type ServerHello struct {
	Version           uint16      `json:"version,omitempty"`
	Random            [32]byte    `json:"random,omitempty"`
	SessionIDLength   uint8       `json:"sessionIDLength,omitempty"`
	SessionID         []byte      `json:"sessionID,omitempty"`
	CipherSuite       uint16      `json:"cipherSuite,omitempty"`
	CompressionMethod uint8       `json:"compressionMethod,omitempty"`
	ExtensionsLength  uint16      `json:"extensionsLength,omitempty"`
	Extensions        []Extension `json:"extensions,omitempty"`
}

func (s *ServerHello) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, s.Version)
	serverHello := append(version, append(s.Random[:], append([]byte{s.SessionIDLength}, s.SessionID...)...)...)
	cipherSuite := make([]byte, 2)
	binary.BigEndian.PutUint16(cipherSuite, s.CipherSuite)
	serverHello = append(serverHello, append(cipherSuite, s.CompressionMethod)...)
	extensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(extensionsLength, s.ExtensionsLength)
	serverHello = append(serverHello, extensionsLength...)
	for _, extension := range s.Extensions {
		serverHello = append(serverHello, extension.GetRaw()...)
	}
	return serverHello
}
