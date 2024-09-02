package mitm

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"socks2https/pkg/crypt"
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

var PRF = map[uint16]prf{
	VersionTLS100: TLS100to101PRF,
	VersionTLS101: TLS100to101PRF,
	VersionTLS102: TLS102PRF,
}

type prf func(secret, label, seed []byte, outputLength int) []byte

var TLS100to101PRF = prf(func(secret, label, seed []byte, outputLength int) []byte {
	pMD5 := crypt.PHash(secret, append(label, seed...), outputLength, md5.New)
	pSHA1 := crypt.PHash(secret, append(label, seed...), outputLength, sha1.New)
	return crypt.XOR(pMD5, pSHA1)[:outputLength]
})

var TLS102PRF = prf(func(secret, label, seed []byte, outputLength int) []byte {
	pSHA256 := crypt.PHash(secret, append(label, seed...), outputLength, sha256.New)
	return pSHA256[:outputLength]
})
