package mitm

import "fmt"

type ChangeCipherSpec byte

func (c *ChangeCipherSpec) GetRaw() []byte {
	return []byte{byte(*c)}
}

func ParseChangeCipherSpec(data []byte) (*ChangeCipherSpec, error) {
	if len(data) != 1 {
		return nil, fmt.Errorf("ChangeCipherSpec is invaild")
	}
	changeCipherSpec := ChangeCipherSpec(data[0])
	return &changeCipherSpec, nil
}
