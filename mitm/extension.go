package mitm

import (
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
)

const (
	ExtensionTypeServerName                          uint16 = 0x0000 // server_name
	ExtensionTypeMaxFragmentLength                   uint16 = 0x0001 // max_fragment_length
	ExtensionTypeStatusRequest                       uint16 = 0x0005 // status_request
	ExtensionTypeSupportedGroups                     uint16 = 0x000a // supported_groups (formerly known as "elliptic_curves")
	ExtensionTypeSignatureAlgorithms                 uint16 = 0x000d // signature_algorithms
	ExtensionTypeUseSrtp                             uint16 = 0x000e // use_srtp
	ExtensionTypeHeartbeat                           uint16 = 0x000f // heartbeat
	ExtensionTypeApplicationLayerProtocolNegotiation uint16 = 0x0010 // application_layer_protocol_negotiation (ALPN)
	ExtensionTypeSignedCertificateTimestamp          uint16 = 0x0012 // signed_certificate_timestamp
	ExtensionTypeClientCertificateType               uint16 = 0x0013 // client_certificate_type
	ExtensionTypeServerCertificateType               uint16 = 0x0014 // server_certificate_type
	ExtensionTypePadding                             uint16 = 0x0015 // padding
	ExtensionTypePreSharedKey                        uint16 = 0x0029 // pre_shared_key (TLS 1.3)
	ExtensionTypeEarlyData                           uint16 = 0x002a // early_data (TLS 1.3)
	ExtensionTypeSupportedVersions                   uint16 = 0x002b // supported_versions (TLS 1.3)
	ExtensionTypeCookie                              uint16 = 0x002c // cookie (TLS 1.3)
	ExtensionTypePskKeyExchangeModes                 uint16 = 0x002d // psk_key_exchange_modes (TLS 1.3)
	ExtensionTypeCertificateAuthorities              uint16 = 0x002f // certificate_authorities (TLS 1.3)
	ExtensionTypeOidFilters                          uint16 = 0x0030 // oid_filters (TLS 1.3)
	ExtensionTypePostHandshakeAuth                   uint16 = 0x0031 // post_handshake_auth (TLS 1.3)
	ExtensionTypeSignatureAlgorithmsCert             uint16 = 0x0032 // signature_algorithms_cert (TLS 1.3)
	ExtensionTypeKeyShare                            uint16 = 0x0033 // key_share (TLS 1.3)
)

type Extension struct {
	Type       uint16     `json:"type"`
	Length     uint16     `json:"length"`
	Payload    []byte     `json:"payload,omitempty"`
	ServerName ServerName `json:"serverName,omitempty"`
}

func ParseExtension(data []byte) (*Extension, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("Extension is invaild")
	}
	extension := &Extension{
		Type:   binary.BigEndian.Uint16(data[0:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}
	if len(data) < 4+int(extension.Length) {
		return nil, fmt.Errorf("Extension is incomplete")
	}
	extension.Payload = data[4 : 4+extension.Length]
	switch extension.Type {
	case ExtensionTypeServerName:
		serverName, err := ParseServerName(extension.Payload)
		if err != nil {
			return nil, fmt.Errorf("parse ServerName failed : %v", err)
		}
		extension.ServerName = *serverName
	}
	return extension, nil
}

func (e *Extension) GetRaw() []byte {
	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, e.Type)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, e.Length)
	extension := append(typ, length...)
	if e.Payload == nil {
		switch e.Type {
		case ExtensionTypeServerName:
			return append(extension, e.ServerName.GetRaw()...)
		default:
			yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("not support Extension Type : %d", e.Type)))
		}
	}
	return append(extension, e.Payload...)
}

type ServerName struct {
	ListLength uint16 `json:"listLength"`
	List       []struct {
		Type   uint8  `json:"type"`
		Length uint16 `json:"length"`
		Name   string `json:"name"`
	} `json:"list"`
}

func ParseServerName(data []byte) (*ServerName, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ServerName is invaild")
	}
	serverName := &ServerName{ListLength: binary.BigEndian.Uint16(data[:2])}
	if len(data) != 2+int(serverName.ListLength) {
		return nil, fmt.Errorf("ServerName is incomplete")
	}
	offset := 2
	for i := 0; offset < len(data); i++ {
		if offset+3 > len(data) {
			return nil, fmt.Errorf("ServerName Payload is invalid")
		}
		payload := struct {
			Type   uint8  `json:"type"`
			Length uint16 `json:"length"`
			Name   string `json:"name"`
		}{}
		payload.Type, payload.Length = data[offset], binary.BigEndian.Uint16(data[offset:offset+2])
		offset += 3
		index := offset + int(payload.Length)
		if index > len(data) {
			return nil, fmt.Errorf("ServerName Payload is incomplete")
		}
		payload.Name = string(data[offset:index])
		offset = index
		serverName.List = append(serverName.List, payload)
	}
	return serverName, nil
}

func (s *ServerName) GetRaw() []byte {
	listLength := make([]byte, 2)
	binary.BigEndian.PutUint16(listLength, s.ListLength)
	serverName := listLength
	for _, payload := range s.List {
		serverName = append(serverName, payload.Type)
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, payload.Length)
		serverName = append(serverName, length...)
		serverName = append(serverName, []byte(payload.Name)...)
	}
	return serverName
}
