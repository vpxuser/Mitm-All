package crypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"hash"
	"socks2https/pkg/comm"
)

const (
	LabelMasterSecret             = "master secret"
	LabelKeyExpansion             = "key expansion"
	LabelClientFinished           = "client finished"
	LabelServerFinished           = "server finished"
	LabelClientEAPMasterSecret    = "client EAP master secret"
	LabelServerEAPMasterSecret    = "server EAP master secret"
	LabelExtendedMasterSecret     = "extended master secret"
	LabelResumptionMasterSecret   = "resumption master secret"
	LabelExporterMasterSecret     = "exporter master secret"
	LabelEarlyTrafficSecret       = "early traffic secret"
	LabelHandshakeTrafficSecret   = "handshake traffic secret"
	LabelApplicationTrafficSecret = "application traffic secret"
	LabelExporter                 = "EXPORTER"
	LabelFinished                 = "finished"
	LabelBinding                  = "binding"
	LabelSessionTicket            = "session ticket"
)

type PRF func(secret, label, seed []byte, outputLength int) []byte

var TLS100to101PRF = PRF(func(secret, label, seed []byte, outputLength int) []byte {
	pMD5 := PHash(secret, append(label, seed...), outputLength, md5.New)
	pSHA1 := PHash(secret, append(label, seed...), outputLength, sha1.New)
	return XOR(pMD5, pSHA1)[:outputLength]
})

var TLS102PRF = PRF(func(secret, label, seed []byte, outputLength int) []byte {
	pSHA256 := PHash(secret, append(label, seed...), outputLength, sha256.New)
	return pSHA256[:outputLength]
})

type BulkCipher func()

type ConnectionStates struct {
	Domain string

	PRF        PRF
	BulkCipher BulkCipher
}

func Label(label string) []byte {
	return []byte(label)
}

func HmacHash(secret, A []byte, hashFunc func() hash.Hash) []byte {
	hmacFunc := hmac.New(hashFunc, secret)
	hmacFunc.Write(A)
	return hmacFunc.Sum(nil)
}

func PHash(secret, seed []byte, outputLength int, hashFunc func() hash.Hash) []byte {
	var result []byte
	A := seed
	for len(result) < outputLength {
		A = HmacHash(secret, A, hashFunc)
		result = append(result, HmacHash(secret, append(A, seed...), hashFunc)...)
	}
	return result
}

func XOR(pMD5, pSHA1 []byte) []byte {
	var result []byte
	for i := 0; i < len(pMD5); i++ {
		result = append(result, pMD5[i]^pSHA1[i])
	}
	return result
}

func MAC(macKey []byte, seqNum uint64, record []byte, hashFunc func() hash.Hash) []byte {
	seqNumRaw := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumRaw, seqNum)
	A := append(seqNumRaw, record...)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("A Length : %d , A Data : %v", len(A), A)))
	hashMAC := HmacHash(macKey, A, hashFunc)
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Hash MAC Length : %d , Hash MAC Data : %v", len(hashMAC), hashMAC)))
	return hashMAC
}

//func PRF(version uint16, secret, label, seed []byte, outputLength int) []byte {
//	switch version {
//	case mitm.VersionTLS100, mitm.VersionTLS101:
//		pMD5 := PHash(secret, append(label, seed...), outputLength, md5.New)
//		pSHA1 := PHash(secret, append(label, seed...), outputLength, sha1.New)
//		return XOR(pMD5, pSHA1)[:outputLength]
//	case mitm.VersionTLS102:
//		pSHA256 := PHash(secret, append(label, seed...), outputLength, sha256.New)
//		return pSHA256[:outputLength]
//	default:
//		yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, "Un Support Version PRF Algorithm"))
//		return nil
//	}
//}
