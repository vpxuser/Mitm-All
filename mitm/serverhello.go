package mitm

import (
	"encoding/binary"
)

type ServerHello struct {
	Version           uint16      `json:"version"`
	Random            [32]byte    `json:"random"`
	SessionIDLength   uint8       `json:"sessionIDLength"`
	SessionID         []byte      `json:"sessionID"`
	CipherSuite       uint16      `json:"cipherSuite"`
	CompressionMethod uint8       `json:"compressionMethod"`
	ExtensionsLength  uint16      `json:"extensionsLength"`
	Extensions        []Extension `json:"extensions,omitempty"`
}

func (s *ServerHello) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, s.Version)
	serverHello := append(version, s.Random[:]...)
	serverHello = append(serverHello, s.SessionIDLength)
	serverHello = append(serverHello, s.SessionID...)
	cipherSuite := make([]byte, 2)
	binary.BigEndian.PutUint16(cipherSuite, s.CipherSuite)
	serverHello = append(serverHello, cipherSuite...)
	serverHello = append(serverHello, s.CompressionMethod)
	extensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(extensionsLength, s.ExtensionsLength)
	serverHello = append(serverHello, extensionsLength...)
	for _, extension := range s.Extensions {
		serverHello = append(serverHello, extension.GetRaw()...)
	}
	return serverHello
}
