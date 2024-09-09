package mitm

import (
	"bufio"
	"fmt"
	"socks2https/pkg/comm"
	"socks2https/pkg/tlsutils"
)

func readUnknownRecord(data []byte, ctx *Context) (*Record, error) {
	if ctx.ClientEncrypted && data[0] != ContentTypeChangeCipherSpec {
		record, err := ParseBlockRecord(data, ctx)
		if err != nil {
			return nil, err
		}
		return record, nil
	}
	record, err := ParseRecord(data, ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func FilterRecord(reader *bufio.Reader, contentType uint8, handshakeType uint8, ctx *Context) (*Record, error) {
	unknownRecord, err := tlsutils.ReadTLSRecord(reader)
	if err != nil {
		return nil, err
	}

	record, err := readUnknownRecord(unknownRecord, ctx)
	if err != nil {
		return nil, err
	}

	if record.ContentType != contentType {
		switch record.ContentType {
		case ContentTypeAlert:
			alertLevel := comm.SetColor(comm.RED_COLOR_TYPE, AlertLevel[record.Alert.Level])
			alertDescription := comm.SetColor(comm.RED_COLOR_TYPE, AlertDescription[record.Alert.Description])
			return nil, fmt.Errorf("[%s] [%s] %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Alert"), alertLevel, alertDescription)
		default:
			return nil, fmt.Errorf("not supported Content Type : %v , Value : %d", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), record.ContentType)
		}
	}

	if record.ContentType == ContentTypeHandshake && record.Handshake.HandshakeType != handshakeType {
		return nil, fmt.Errorf("[%s] [%s] Unknown Handshake Type : %d", comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"), comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]), record.Handshake.HandshakeType)
	}
	return record, nil
}
