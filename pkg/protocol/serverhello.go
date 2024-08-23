package protocol

import "encoding/binary"

type ServerHello struct {
	Version           uint16      `json:"version"`
	Random            [32]byte    `json:"random"`
	SessionID         []byte      `json:"sessionID"`
	CipherSuite       uint16      `json:"cipherSuite"`
	CompressionMethod uint8       `json:"compressionMethod"`
	Extensions        []Extension `json:"extensions"`
}

func (s *ServerHello) GetRaw() []byte {
	version := make([]byte, 2)
	binary.BigEndian.PutUint16(version, s.Version)
	header := append(version, s.Random[:]...)
	sessionIDLength := len(s.SessionID)
	header = append(header, byte(sessionIDLength))
	header = append(header, s.SessionID...)
	cipherSuite := make([]byte, 2)
	binary.BigEndian.PutUint16(cipherSuite, s.CipherSuite)
	header = append(header, cipherSuite...)
	header = append(header, s.CompressionMethod)
	extensions := GetRawExtensions(s.Extensions)
	extensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(extensionsLength, uint16(len(extensions)))
	header = append(header, extensionsLength...)
	return append(header, extensions...)
}
