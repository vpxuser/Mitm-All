package tlsutils

func NewApplicationData(version uint16, fragment []byte) (*Record, error) {
	return &Record{
		ContentType:     ContentTypeApplicationData,
		Version:         version,
		Length:          uint16(len(fragment)),
		Fragment:        fragment,
		ApplicationData: fragment,
	}, nil
}
