package mitm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"socks2https/pkg/comm"
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
	header := make([]byte, 5)
	if _, err := reader.Read(header); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Header failed : %v", err)
	}

	length := binary.BigEndian.Uint16(header[3:5])

	fragment := make([]byte, length)
	if _, err := reader.Read(fragment); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Fragment failed : %v", err)
	}

	record, err := readUnknownRecord(append(header, fragment...), ctx)
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
