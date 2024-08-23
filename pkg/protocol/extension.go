package protocol

import (
	"bytes"
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
	Type                 uint16               `json:"type"`
	Length               uint16               `json:"length"`
	Data                 []byte               `json:"data"`
	ServerNameIndication ServerNameIndication `json:"serverNameIndication"`
}

// ServerNameIndication 代表 TLS 中的 SNI 扩展
type ServerNameIndication struct {
	ServerNameListLength uint16       `json:"serverNameListLength"`
	ServerNameList       []ServerName `json:"serverNameList"`
}

// ServerName 代表 SNI 中的单个服务器名称
type ServerName struct {
	NameType   uint8  `json:"nameType"`
	NameLength uint16 `json:"nameLength"`
	HostName   string `json:"hostName"`
}

func ParseExtensions(data []byte) ([]Extension, error) {
	reader := bytes.NewReader(data)
	var extensions []Extension
	for remaining := uint16(len(data)); remaining > 0; {
		extension := &Extension{}
		if err := binary.Read(reader, binary.BigEndian, &extension.Type); err != nil {
			return nil, fmt.Errorf("failed to read extension type: %w", err)
		}
		if err := binary.Read(reader, binary.BigEndian, &extension.Length); err != nil {
			return nil, fmt.Errorf("failed to read extension length: %w", err)
		}
		extension.Data = make([]byte, extension.Length)
		if _, err := reader.Read(extension.Data[:]); err != nil {
			return nil, fmt.Errorf("failed to read extension data: %w", err)
		}
		remaining -= (2 + 2 + extension.Length) // Type (2 bytes) + Length (2 bytes) + Data
		switch extension.Type {
		case ExtensionTypeServerName:
			serverNameIndication, err := ParseServerNameIndication(extension.Data)
			if err != nil {
				yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("parse ServerNameIndication failed : %v", err)))
				continue
			}
			extension.ServerNameIndication = *serverNameIndication
			//extensionJSON, _ := json.MarshalIndent(extension, "", "  ")
			//yaklog.Debugf("SNI:\n%s", extensionJSON)
		}
		extensions = append(extensions, *extension)
	}
	return extensions, nil
}

func ParseServerNameIndication(data []byte) (*ServerNameIndication, error) {
	// 确保数据长度足够
	if len(data) < 2 {
		return nil, fmt.Errorf("Extension Data is invaild")
	}
	sni := &ServerNameIndication{}
	offset := 0
	// 解析 ServerNameListLength
	sni.ServerNameListLength = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	// 解析 ServerName 列表
	for offset < len(data) {
		if offset+3 > len(data) {
			return nil, fmt.Errorf("Server Name Entry is invalid")
		}
		serverName := &ServerName{}
		serverName.NameType = data[offset]
		offset += 1
		serverName.NameLength = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if offset+int(serverName.NameLength) > len(data) {
			return nil, fmt.Errorf("Server Name Length is invalid")
		}
		serverName.HostName = string(data[offset : offset+int(serverName.NameLength)])
		offset += int(serverName.NameLength)
		sni.ServerNameList = append(sni.ServerNameList, *serverName)
	}
	return sni, nil
}

func (sni *ServerNameIndication) GetRaw() []byte {
	serverNameListLength := make([]byte, 2)
	binary.BigEndian.PutUint16(serverNameListLength, sni.ServerNameListLength)
	extension := serverNameListLength
	for _, serverName := range sni.ServerNameList {
		extension = append(extension, serverName.NameType)
		nameLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nameLength, serverName.NameLength)
		extension = append(extension, nameLength...)
		extension = append(extension, []byte(serverName.HostName)...)
	}
	return extension
}

func (e *Extension) GetRaw() []byte {
	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, e.Type)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, e.Length)
	header := append(typ, length...)
	switch true {
	case &e.ServerNameIndication != nil:
		return append(header, e.ServerNameIndication.GetRaw()...)
	}
	return append(header, e.Data...)
}

func GetRawExtensions(extensions []Extension) []byte {
	var data []byte
	for _, extension := range extensions {
		data = append(data, extension.GetRaw()...)
	}
	return data
}
