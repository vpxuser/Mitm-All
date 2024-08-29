package mitm

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
)

type ReadRecord func(reader *bufio.Reader, ctx *Context)

var TLSMITMPipeLine []ReadRecord

func TLSMITM(reader *bufio.Reader, client net.Conn, ctx *Context) {
	defer client.Close()

	ctx.HandshakeType = HandshakeTypeClientHello
	clientHelloRaw, err := FilterRecord(reader, ContentTypeHandshake, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, clientHelloRaw)
	clientHello, err := ParseRecord(clientHelloRaw, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.ClientHello = *clientHello
	domain, ok := clientHello.GetDomain()
	if !ok {
		yaklog.Errorf("%s Domain is empty", ctx.Client2MitmLog)
		return
	}
	ctx.Domain = domain
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , Domain : %s", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[clientHello.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[clientHello.Handshake.HandshakeType])), comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))

	serverHello, err := NewServerHello(clientHello, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.ServerHello = *serverHello
	serverHelloRaw := serverHello.GetRaw()
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, serverHelloRaw)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[serverHello.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[serverHello.Handshake.HandshakeType])))
	if _, err = client.Write(serverHelloRaw); err != nil {
		yaklog.Errorf("%s write Server Hello failed : %v", ctx.Mitm2ClientLog, err)
		return
	}

	certificate, err := NewCertificate(cert.CertificateAndPrivateKeyPath, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.Certificate = *certificate
	certificateRaw := certificate.GetRaw()
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, certificateRaw)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[certificate.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[certificate.Handshake.HandshakeType])))
	if _, err = client.Write(certificateRaw); err != nil {
		yaklog.Errorf("%s write Certificate failed : %v", ctx.Mitm2ClientLog, err)
		return
	}

	serverHelloDone := NewServerHelloDone(ctx)
	ctx.ServerHelloDone = *serverHelloDone
	serverHelloDoneRaw := serverHelloDone.GetRaw()
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, serverHelloDoneRaw)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[serverHelloDone.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[serverHelloDone.Handshake.HandshakeType])))
	if _, err = client.Write(serverHelloDoneRaw); err != nil {
		yaklog.Errorf("%s write Server Hello Done failed : %v", ctx.Mitm2ClientLog, err)
		return
	}

	ctx.HandshakeType = HandshakeTypeClientKeyExchange
	clientKeyExchangeRaw, err := FilterRecord(reader, ContentTypeHandshake, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, clientKeyExchangeRaw)
	clientKeyExchange, err := ParseRecord(clientKeyExchangeRaw, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.ClientKeyExchange = *clientKeyExchange
	//clientKeyExchangeJSON, _ := json.MarshalIndent(clientKeyExchange.Handshake.ClientKeyExchange.(*RSAClientKeyExchange), "", "  ")
	//yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , Client Key Exchange :\n%s", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[clientKeyExchange.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[clientKeyExchange.Handshake.HandshakeType])), clientKeyExchangeJSON)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[clientKeyExchange.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[clientKeyExchange.Handshake.HandshakeType])))

	ctx.HandshakeType = 0xFF
	changeCipherSpecRaw, err := FilterRecord(reader, ContentTypeChangeCipherSpec, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	//todo NewChangeCipherSpec()
	yaklog.Debugf("%s Content Type : %s , Change Cipher Spec Raw : %v", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[changeCipherSpecRaw[0]]), changeCipherSpecRaw)

	ctx.HandshakeType = 0xFF
	finishedRaw, err := FilterRecord(reader, ContentTypeHandshake, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.HandshakeRawList = append(ctx.HandshakeRawList, finishedRaw)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[finishedRaw[0]]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[HandshakeTypeFinished])))
	finished, err := ParseRecord(finishedRaw, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
	ctx.Finished = *finished

	//finished, err := NewFinished(ctx)
	//if err != nil {
	//	yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
	//	return
	//} else if _, err = client.Write(finished.GetRaw()); err != nil {
	//	yaklog.Errorf("%s write Finished failed : %v", ctx.Mitm2ClientLog, err)
	//}
	//yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , Server Finished Raw : %v", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[finished.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[HandshakeTypeFinished])), finished.GetRaw())

	ctx.HandshakeType = 0xFF
	_, err = FilterRecord(reader, ContentTypeHandshake, ctx)
	if err != nil {
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return
	}
}

func FilterRecord(reader *bufio.Reader, contentType uint8, ctx *Context) ([]byte, error) {
	recordHeader := make([]byte, 5)
	if _, err := reader.Read(recordHeader); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Header from Client failed : %v", err)
	}
	if recordHeader[0] != contentType {
		return nil, ReadUnkonwnRecord(recordHeader, reader, ctx)
	}
	length := binary.BigEndian.Uint16(recordHeader[3:5])
	recordFragment := make([]byte, length)
	if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Fragment failed : %v", err)
	}
	record := append(recordHeader, recordFragment...)
	if recordFragment[0] == ctx.HandshakeType || ctx.HandshakeType == 0xFF {
		return record, nil
	}
	return nil, ReadUnknownHandshake(record, reader, ctx)
}

func ReadUnkonwnRecord(recordHeader []byte, reader *bufio.Reader, ctx *Context) error {
	contentType := recordHeader[0]
	switch contentType {
	case ContentTypeAlert:
		length := binary.BigEndian.Uint16(recordHeader[3:5])
		recordFragment := make([]byte, length)
		if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Fragment failed : %v", err)
		}
		alert, err := ParseAlert(recordFragment, ctx)
		if err != nil {
			return fmt.Errorf("Content Type : %s , Decrypt Alert Failed : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[ContentTypeAlert]), comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%v", err)))
		}
		return fmt.Errorf("Content Type : %s , %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[ContentTypeAlert]), comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("[%s] %s", AlertLevel[alert.Level], AlertDescription[alert.Description])))
	case ContentTypeTLSPlaintext:
		return fmt.Errorf("TLS Record is invaild type : %s", ContentType[contentType])
	default:
		return fmt.Errorf("Content Type not supported : %v", contentType)
	}
}

func ReadUnknownHandshake(record []byte, reader *bufio.Reader, ctx *Context) error {
	//todo
	return fmt.Errorf("unknown Handshake Type")
}
