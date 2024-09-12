package crypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
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
	tls.VersionTLS10: TLS10to11PRF,
	tls.VersionTLS11: TLS10to11PRF,
	tls.VersionTLS12: TLS12PRF,
}

type prf func(secret, label, seed []byte, outputLength int) []byte

var TLS10to11PRF = prf(func(secret, label, seed []byte, outputLength int) []byte {
	pMD5 := PHash(secret, append(label, seed...), outputLength, md5.New)
	pSHA1 := PHash(secret, append(label, seed...), outputLength, sha1.New)
	return XOR(pMD5, pSHA1)[:outputLength]
})

var TLS12PRF = prf(func(secret, label, seed []byte, outputLength int) []byte {
	pSHA256 := PHash(secret, append(label, seed...), outputLength, sha256.New)
	return pSHA256[:outputLength]
})
