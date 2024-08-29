package mitm

type Protocol interface {
	GetRaw() []byte
}

func GetRaw(protocol Protocol) []byte {
	return protocol.GetRaw()
}
