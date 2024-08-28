package comm

import "bytes"

func Combine(datas [][]byte) []byte {
	var combined bytes.Buffer
	for _, data := range datas {
		combined.Write(data)
	}
	return combined.Bytes()
}
