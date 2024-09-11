package mitm

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/color"
	"time"
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

func NewServerHello(version, cipherSuite uint16) (*Record, error) {
	serverHello := &ServerHello{Version: version}
	binary.BigEndian.PutUint32(serverHello.Random[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(serverHello.Random[4:]); err != nil {
		return nil, fmt.Errorf("create Random failed : %v", err)
	}
	serverHello.SessionIDLength = 32
	serverHello.SessionID = make([]byte, serverHello.SessionIDLength)
	if _, err := rand.Read(serverHello.SessionID); err != nil {
		return nil, fmt.Errorf("create SessionID failed : %v", err)
	}
	serverHello.CipherSuite = cipherSuite
	serverHello.CompressionMethod = 0
	serverHello.ExtensionsLength = 0
	serverHelloRaw := serverHello.GetRaw()
	handshake := &Handshake{
		HandshakeType: HandshakeTypeServerHello,
		Length:        uint32(len(serverHelloRaw)),
		ServerHello:   *serverHello,
		Payload:       serverHelloRaw,
	}
	handshakeRaw := handshake.GetRaw()
	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   *handshake,
		Fragment:    handshakeRaw,
	}, nil
}

var WriteServerHello = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Mitm2ClientLog, color.SetColor(color.YELLOW_COLOR_TYPE, "Handshake"), color.SetColor(color.RED_COLOR_TYPE, "Server Hello"))
	record, err := NewServerHello(ctx.Version, ctx.CipherSuite)
	if err != nil {
		return fmt.Errorf("%s %v", tamplate, err)
	}
	ctx.ServerRandom = record.Handshake.ServerHello.Random
	serverHello := record.GetRaw()
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, serverHello[5:])
	if _, err = conn.Write(serverHello); err != nil {
		return fmt.Errorf("%s Write ServerHello Failed : %v", tamplate, err)
	}
	yaklog.Infof("%s Write ServerHello Successfully", tamplate)
	return nil
})
