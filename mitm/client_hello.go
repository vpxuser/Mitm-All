package mitm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/pkg/comm"
)

type ClientHello struct {
	Version                  uint16      `json:"version,omitempty"`
	Random                   [32]byte    `json:"random,omitempty"`
	SessionIDLength          uint8       `json:"sessionIDLength,omitempty"`
	SessionID                []byte      `json:"sessionID,omitempty"`
	CipherSuitesLength       uint16      `json:"cipherSuitesLength,omitempty"`
	CipherSuites             []uint16    `json:"cipherSuites,omitempty"`
	CompressionMethodsLength uint8       `json:"compressionMethodsLength,omitempty"`
	CompressionMethods       []uint8     `json:"compressionMethods,omitempty"`
	ExtensionsLength         uint16      `json:"extensionsLength,omitempty"`
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

var ReadClientHello = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"), comm.SetColor(comm.RED_COLOR_TYPE, "Client Hello"))
	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeClientHello, ctx)
	if err != nil {
		return err
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	clientHello := record.Handshake.ClientHello
	ctx.ClientRandom = record.Handshake.ClientHello.Random
	for _, cipherSuite := range clientHello.CipherSuites {
		if cipherSuite != ctx.CipherSuite {
			continue
		}
		for _, extension := range clientHello.Extensions {
			if extension.Type != ExtensionTypeServerName {
				continue
			}
			ctx.Domain = extension.ServerName.List[0].Name
			yaklog.Infof("%s Domain : %s", tamplate, ctx.Domain)
			return nil
		}
		if domains, ok := IP2Domain[ctx.Host]; ok {
			ctx.Domain = domains[0]
			yaklog.Infof("%s Parse CDN IP %s to Domain %s", tamplate, ctx.Host, ctx.Domain)
			return nil
		}
		// todo defalut Certificate
		ctx.Domain = ctx.DefaultDomain
		yaklog.Infof("%s use Default Domain : %s", tamplate, ctx.Domain)
		return nil
		//return fmt.Errorf("%s query DNS Record failed", tamplate)
	}
	return fmt.Errorf("%s not support Cipher Suites", tamplate)
})
