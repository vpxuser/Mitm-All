package tlsutils

func NewChangeCipherSpec(version uint16) *Record {
	return &Record{
		ContentType: ContentTypeChangeCipherSpec,
		Version:     version,
		Length:      1,
		Fragment:    []byte{0x01},
	}
}
