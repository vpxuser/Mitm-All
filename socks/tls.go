package socks

import (
	"bufio"
	"bytes"
	"encoding/binary"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/pkg/comm"
)

const (
	// TLS Content Type
	Change_Cipher_Spec          byte = 0x14
	Alert                       byte = 0x15
	Handshake                   byte = 0x16
	Application_Data            byte = 0x17
	Heartbeat                   byte = 0x18
	TLS12CID                    byte = 0x19
	ACK                         byte = 0x1a
	Encrypted_Handshake_Message byte = 0x1f // TLS 1.3 Only
	Unknown_Content_Type        byte = 0xff
	// TLS Handshake Type
	ClientHello         byte = 0x01
	ServerHello         byte = 0x02
	New_Session_Ticket  byte = 0x04
	Certificate         byte = 0x0b
	Server_Key_Exchange byte = 0x0c
	ServerHello_Done    byte = 0x0e
	Client_Key_Exchange byte = 0x10
	Finished            byte = 0x14
)

var (
	ContentMap = map[byte]string{
		Change_Cipher_Spec:          "Change_Cipher_Spec",
		Alert:                       "Alert",
		Handshake:                   "Handshake",
		Application_Data:            "Application_Data",
		Heartbeat:                   "Heartbeat",
		TLS12CID:                    "TLS12CID",
		ACK:                         "ACK",
		Encrypted_Handshake_Message: "Encrypted_Handshake_Message ",
		Unknown_Content_Type:        "Unknown_Content_Type",
	}
	HandshakeMap = map[byte]string{
		ClientHello:         "ClientHello",
		ServerHello:         "ServerHello",
		New_Session_Ticket:  "New_Session_Ticket",
		Certificate:         "Certificate",
		Server_Key_Exchange: "Server_Key_Exchange",
		ServerHello_Done:    "ServerHello_Done",
		Client_Key_Exchange: "Client_Key_Exchange",
		Finished:            "Finished",
	}
)

type TLSRecord struct {
	RecordHeader
	RecordPayload interface{}
}

type RecordHeader struct {
	ContentType byte   //1 byte
	Version     uint16 //2 byte
	Length      uint16 //2 byte
}

type TLSHandshake struct {
	HandshakeHeader
	HandshakePayload interface{}
}

type HandshakeHeader struct {
	HandshakeType byte   //1 byte
	Length        uint32 //3 byte
}

type Clienthello struct {
	Version   uint16
	Random    []byte //32 byte
	SessionID struct {
		Length    int
		SessionID []byte
	}
	CipherSuites struct {
		Length       int
		CipherSuites []byte //2x byte
	}
	CompressionMethods struct {
		Length             int
		CompressionMethods []byte //
	}
	Extensions struct {
		Length    int
		Extension []byte
	}
}

// Extension 表示 TLS 扩展字段
type Extension struct {
	Type uint16
	Data []byte
}

func parseClientHello(clientHelloBuf []byte) *Clienthello {
	clientHello := &Clienthello{}
	// 假设 data 是从 ClientHello 的 "Version" 字段开始的数据
	offset := 0
	// 读取 Version (2 bytes)
	clientHello.Version = binary.BigEndian.Uint16(clientHelloBuf[offset : offset+2])
	offset += 2
	// 跳过 Random (32 bytes)
	offset += 32
	// 读取 Session ID 长度 (1 byte)
	clientHello.SessionID.Length = int(clientHelloBuf[offset])
	yaklog.Debugf("SessionID Length : %d", clientHello.SessionID.Length)
	offset++
	// 跳过 Session ID
	offset += clientHello.SessionID.Length
	// 读取 Cipher Suites 长度 (2 bytes)
	clientHello.CipherSuites.Length = int(binary.BigEndian.Uint16(clientHelloBuf[offset : offset+2]))
	yaklog.Debugf("CipherSuites Length : %d", clientHello.CipherSuites.Length)
	offset += 2
	// 跳过 Cipher Suites
	offset += clientHello.CipherSuites.Length
	// 读取 Compression Methods 长度 (1 byte)
	clientHello.CompressionMethods.Length = int(clientHelloBuf[offset])
	yaklog.Debugf("CompressionMethods Length : %d", clientHello.CompressionMethods.Length)
	offset++
	// 跳过 Compression Methods
	offset += clientHello.CompressionMethods.Length
	// 读取 Extensions 长度 (2 bytes)
	if len(clientHelloBuf[offset:]) < 2 {
		return clientHello
	}
	clientHello.Extensions.Length = int(binary.BigEndian.Uint16(clientHelloBuf[offset : offset+2]))
	yaklog.Debugf("Extensions Length : %d", clientHello.Extensions.Length)
	offset += 2
	// 解析扩展字段
	clientHello.Extensions.Extension = clientHelloBuf[offset : offset+clientHello.Extensions.Length]
	return clientHello
}

func parseSNI(extensions []byte) string {
	reader := bufio.NewReader(bytes.NewReader(extensions))
	for i := 0; i < len(extensions); {
		header := make([]byte, 4)
		if _, err := reader.Read(header); err != nil {
			return ""
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[2:4]))
		if _, err := reader.Read(payload); err != nil {
			return ""
		}
		if binary.BigEndian.Uint16(header[0:2]) != 0x00 {
			continue
		} else {
			return string(payload[5:])
		}
	}
	return ""
}

func parseTLSHandshake(reader *bufio.Reader) (byte, error) {
	handshakeHeader, err := reader.Peek(9)
	if err != nil {
		return Unknown_Content_Type, err
	}
	//if handshakeHeader[0] != Handshake {
	//	return 0xff, fmt.Errorf("not tls handshake")
	//}
	switch handshakeHeader[5] {
	case ClientHello:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "ClientHello"))
		return ClientHello, nil
	case ServerHello:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "ServerHello"))
		return ServerHello, nil
	case New_Session_Ticket:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "New_Session_Ticket"))
		return New_Session_Ticket, nil
	case Certificate:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Certificate"))
		return Certificate, nil
	case Server_Key_Exchange:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Server_Key_Exchange"))
		return Server_Key_Exchange, nil
	case ServerHello_Done:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "ServerHello_Done"))
		return ServerHello_Done, nil
	case Client_Key_Exchange:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Client_Key_Exchange"))
		return Client_Key_Exchange, nil
	case Finished:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished"))
		return Finished, nil
	default:
		yaklog.Debugf("Handshake Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished"))
		return Finished, nil
	}
}

func parseTLSRecord(reader *bufio.Reader) (byte, error) {
	recordHeader, err := reader.Peek(1)
	if err != nil {
		return Unknown_Content_Type, err
	}
	switch recordHeader[0] {
	case Change_Cipher_Spec:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Change_Cipher_Spec"))
		return Change_Cipher_Spec, nil
	case Alert:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Alert"))
		return Alert, nil
	case Handshake:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"))
		return Handshake, nil
	case Application_Data:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Application_Data"))
		return Application_Data, nil
	case Heartbeat:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Heartbeat"))
		return Heartbeat, nil
	case Encrypted_Handshake_Message:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Encrypted_Handshake_Message"))
		return Encrypted_Handshake_Message, nil
	default:
		yaklog.Debugf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Unknown_Content_Type"))
		return Unknown_Content_Type, nil
	}
}

//func readTLSRecord(reader *bufio.Reader) ([]byte, error) {
//	recordHeader := make([]byte, 5)
//	if _, err := reader.Read(recordHeader); err != nil {
//		return nil, fmt.Errorf("read tls record header failed : %v", err)
//	}
//	//contentType := recordHeader[0]
//	//version := binary.BigEndian.Uint16(recordHeader[1:3])
//	length := binary.BigEndian.Uint16(recordHeader[3:5])
//	//yaklog.Debugf("%v", &RecordHeader{ContentType: contentType, Version: version, Length: length})
//	recordPayload := make([]byte, length)
//	if _, err := reader.Read(recordPayload); err != nil {
//		return nil, fmt.Errorf("read tls record payload failed : %v", err)
//	}
//	return append(recordHeader, recordPayload...), nil
//}
