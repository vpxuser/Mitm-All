package comm

import (
	"hash"
)

func CombineHash(datas [][]byte, hashFunc func() hash.Hash) []byte {
	h := hashFunc()
	for _, data := range datas {
		h.Write(data)
	}
	return h.Sum(nil)
}
