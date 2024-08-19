package tsocks

import (
	"bufio"
	"encoding/binary"
	"fmt"
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
	HandshakeType byte //1 byte
	Length        uint //3 byte
}

func parseTLSHandshake(reader *bufio.Reader) (byte, error) {
	handshakeHeader, err := reader.Peek(9)
	if err != nil {
		return Unknown_Content_Type, fmt.Errorf("parse tls handshake failed : %v", err)
	}
	if handshakeHeader[0] != Handshake {
		return 0xff, fmt.Errorf("not tls handshake")
	}
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
		return 0xff, fmt.Errorf("unkonwn tls handshake type")
	}
}

func parseTLSRecord(reader *bufio.Reader) (byte, error) {
	recordHeader, err := reader.Peek(1)
	if err != nil {
		return Unknown_Content_Type, fmt.Errorf("parse tls record failed: %v", err)
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
		return Unknown_Content_Type, fmt.Errorf("unkonwn tls record failed: %v", err)
	}
}

func readTLSRecord(reader *bufio.Reader) ([]byte, error) {
	recordHeader := make([]byte, 5)
	if _, err := reader.Read(recordHeader); err != nil {
		return nil, fmt.Errorf("read tls record header failed : %v", err)
	}
	contentType := recordHeader[0]
	version := binary.BigEndian.Uint16(recordHeader[1:3])
	length := binary.BigEndian.Uint16(recordHeader[3:5])
	yaklog.Debugf("%v", &RecordHeader{ContentType: contentType, Version: version, Length: length})
	recordPayload := make([]byte, length)
	if _, err := reader.Read(recordPayload); err != nil {
		return nil, fmt.Errorf("read tls record payload failed : %v", err)
	}
	return append(recordHeader, recordPayload...), nil
}
