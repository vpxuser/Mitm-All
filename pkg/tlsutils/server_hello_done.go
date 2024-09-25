package tlsutils

// NewServerHelloDone 创建一个ServerHelloDone消息记录
func NewServerHelloDone(version uint16) *Record {
	handshake := &Handshake{
		HandshakeType: HandshakeTypeServerHelloDone,
		Length:        0,
	}
	handshakeRaw := handshake.GetRaw()

	return &Record{
		ContentType: ContentTypeHandshake,
		Version:     version,
		Length:      uint16(len(handshakeRaw)),
		Handshake:   handshake,
		Fragment:    handshakeRaw,
	}
}
