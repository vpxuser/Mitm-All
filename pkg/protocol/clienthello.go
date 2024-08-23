package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	// TLS 1.2 Cipher Suites
	TLS_RSA_WITH_AES_128_CBC_SHA          uint16 = 0x002F
	TLS_RSA_WITH_AES_256_CBC_SHA          uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256       uint16 = 0x003C
	TLS_RSA_WITH_AES_256_CBC_SHA256       uint16 = 0x003D
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    uint16 = 0xC013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    uint16 = 0xC014
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 uint16 = 0xC027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 uint16 = 0xC028

	// TLS 1.3 Cipher Suites
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
	TLS_AES_128_CCM_SHA256       uint16 = 0x1304
	TLS_AES_128_CCM_8_SHA256     uint16 = 0x1305

	// Other Common Cipher Suites
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xC02B
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xC02C
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xC02F
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xC030
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xCCA9
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xCCA8
)

var CipherSuitesLowVersion = map[uint16]uint16{
	TLS_RSA_WITH_AES_128_CBC_SHA:          TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA:          TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA256:       TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA256:       TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
}

type ClientHello struct {
	Version            uint16      `json:"version"`
	Random             [32]byte    `json:"random"`
	SessionID          []byte      `json:"sessionID"`
	CipherSuites       []uint16    `json:"cipherSuites"`
	CompressionMethods []uint8     `json:"compressionMethods"`
	Extensions         []Extension `json:"extensions"`
}

// ParseClientHello 解析Clienthello函数
func ParseClientHello(data []byte) (*ClientHello, error) {
	reader := bytes.NewReader(data)
	clientHello := &ClientHello{}
	// 解析 TLS 版本
	if err := binary.Read(reader, binary.BigEndian, &clientHello.Version); err != nil {
		return nil, fmt.Errorf("parse ClientHello Version failed : %v", err)
	}
	// 解析随机数
	if _, err := reader.Read(clientHello.Random[:]); err != nil {
		return nil, fmt.Errorf("parse ClientHello Random failed : %v", err)
	}
	// 解析 Session ID
	var sessionIDLength uint8
	if err := binary.Read(reader, binary.BigEndian, &sessionIDLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello SessionID Length failed : %v", err)
	}
	clientHello.SessionID = make([]byte, sessionIDLength)
	if _, err := reader.Read(clientHello.SessionID); err != nil {
		return nil, fmt.Errorf("parse ClientHello SessionID failed : %v", err)
	}
	// 解析 Cipher Suites
	var cipherSuitesLength uint16
	if err := binary.Read(reader, binary.BigEndian, &cipherSuitesLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello CipherSuites Length failed : %v", err)
	}
	numCipherSuites := cipherSuitesLength / 2
	clientHello.CipherSuites = make([]uint16, numCipherSuites)
	if err := binary.Read(reader, binary.BigEndian, clientHello.CipherSuites); err != nil {
		return nil, fmt.Errorf("parse ClientHello CipherSuites failed : %v", err)
	}
	// 解析 Compression Methods
	var compressionMethodsLength uint8
	if err := binary.Read(reader, binary.BigEndian, &compressionMethodsLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello CompressionMethods Length failed : %v", err)
	}
	clientHello.CompressionMethods = make([]uint8, compressionMethodsLength)
	if _, err := reader.Read(clientHello.CompressionMethods); err != nil {
		return nil, fmt.Errorf("parse ClientHello CompressionMethods failed : %v", err)
	}
	// 解析 Extensions
	var extensionsLength uint16
	if err := binary.Read(reader, binary.BigEndian, &extensionsLength); err != nil {
		return nil, fmt.Errorf("parse ClientHello Extensions Length failed : %v", err)
	}
	extensions := make([]byte, extensionsLength)
	if _, err := reader.Read(extensions); err != nil {
		return nil, fmt.Errorf("parse ClientHello Extensions failed : %v", err)
	}
	var err error
	clientHello.Extensions, err = ParseExtensions(extensions)
	if err != nil {
		return nil, err
	}
	return clientHello, nil
}

func (c *ClientHello) GenrateServerHello() (*ServerHello, error) {
	serverHello := &ServerHello{Version: c.Version}
	binary.BigEndian.PutUint32(serverHello.Random[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(serverHello.Random[4:]); err != nil {
		return nil, fmt.Errorf("generate SessionID failed : %v", err)
	}
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("generate SessionID failed : %v", err)
	}
	serverHello.SessionID = sessionID
	continueSwitch := false
	for _, cipherSuite := range c.CipherSuites {
		if cipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA {
			continueSwitch = true
			serverHello.CipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA
			break
		}
	}
	if !continueSwitch {
		return nil, fmt.Errorf("no supported CipherSuites found")
	}
	serverHello.CompressionMethod = 0
	return serverHello, nil
}
