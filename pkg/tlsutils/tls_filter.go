package tlsutils

import (
	"bufio"
	"fmt"
	"socks2https/context"
	"socks2https/pkg/colorutils"
)

func readUnknownRecord(data []byte, ctx *context.Context) (*Record, error) {
	if ctx.TLSContext.ClientEncrypted && data[0] != ContentTypeChangeCipherSpec {
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

// FilterRecord 消息记录过滤器，过滤出想要的消息记录类型
func FilterRecord(reader *bufio.Reader, contentType uint8, handshakeType uint8, ctx *context.Context) (*Record, error) {
	unknownRecord, err := ReadTLSRecord(reader)
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
			alertLevel := colorutils.SetColor(colorutils.RED_COLOR_TYPE, AlertLevel[record.Alert.Level])
			alertDescription := colorutils.SetColor(colorutils.RED_COLOR_TYPE, AlertDescription[record.Alert.Description])
			return nil, fmt.Errorf("[%s] [%s] %s", colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Alert"), alertLevel, alertDescription)
		default:
			return nil, fmt.Errorf("not supported Content Type : %v , Value : %d", colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), record.ContentType)
		}
	}

	if record.ContentType == ContentTypeHandshake && record.Handshake.HandshakeType != handshakeType {
		return nil, fmt.Errorf("[%s] [%s] Unknown Handshake Type : %d", colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]), record.Handshake.HandshakeType)
	}
	return record, nil
}
