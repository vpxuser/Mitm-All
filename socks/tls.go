package socks

import (
	"bufio"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
	"socks2https/pkg/protocol"
)

func TLSMITM(reader *bufio.Reader, client net.Conn, ctx *Context) error {
	defer client.Close()
	clientId := ctx.GetClientId()
	client2MitmLog := fmt.Sprintf("%s [%s ==> %s]", clientId, client.RemoteAddr().String(), client.LocalAddr().String())
	mitm2ClientLog := fmt.Sprintf("%s [%s ==> %s]", clientId, client.LocalAddr().String(), client.RemoteAddr().String())
	record, err := FilterRecord(reader, protocol.ContentTypeHandshake, protocol.HandshakeTypeClientHello, ctx)
	if err != nil {
		return err
	}
	recordList := record
	clientHello, err := protocol.ParseRecord(record)
	if err != nil {
		return err
	}
	domain, ok := clientHello.GetDomain()
	if ok {
		yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , Domain : %s", client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[clientHello.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[clientHello.Handshake.HandshakeType])), comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))
	} else {
		return fmt.Errorf("domain is empty")
	}
	serverHello, err := protocol.NewServerHello(clientHello)
	if err != nil {
		return err
	}
	record = serverHello.GetRaw()
	recordList = append(recordList, record...)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[serverHello.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[serverHello.Handshake.HandshakeType])))
	if _, err = client.Write(record); err != nil {
		return fmt.Errorf("write TLS Record failed : %v", err)
	}
	certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
	if err != nil {
		return err
	}
	record = certificate.GetRaw()
	recordList = append(recordList, record...)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[certificate.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[certificate.Handshake.HandshakeType])))
	if _, err = client.Write(record); err != nil {
		return fmt.Errorf("write TLS Record failed : %v", err)
	}
	serverHelloDone := protocol.NewServerHelloDone()
	record = serverHelloDone.GetRaw()
	recordList = append(recordList, record...)
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[serverHelloDone.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[serverHelloDone.Handshake.HandshakeType])))
	if _, err = client.Write(record); err != nil {
		return fmt.Errorf("write TLS Record failed : %v", err)
	}
	record, err = FilterRecord(reader, protocol.ContentTypeHandshake, protocol.HandshakeTypeClientKeyExchange, ctx)
	if err != nil {
		return err
	}
	recordList = append(recordList, record...)
	clientKeyExchange, err := protocol.ParseRecord(record, protocol.KeyExchangeRSA)
	if err != nil {
		return err
	}
	_, privateKey, err := cert.GetCertificateAndKey(cert.CertificateAndPrivateKeyPath, domain)
	if err != nil {
		return err
	}
	key, iv, err := clientKeyExchange.Handshake.ClientKeyExchange.GetKeyAndIV(privateKey, clientHello.Handshake.ClientHello.Random, serverHello.Handshake.ServerHello.Random, protocol.TLS_RSA_WITH_AES_128_CBC_SHA)
	if err != nil {
		return err
	}
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , AES Key : %v , IV : %v", client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[clientKeyExchange.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[clientKeyExchange.Handshake.HandshakeType])), key, iv)
	ctx.Key = key
	ctx.IV = iv
	record, err = FilterRecord(reader, protocol.ContentTypeChangeCipherSpec, ctx)
	if err != nil {
		return err
	}
	//todo
	//recordList = append(recordList, record...)
	yaklog.Debugf("%s Content Type : %s , Change Cipher Spec Raw : %v", client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[record[0]]), record)
	record, err = FilterRecord(reader, protocol.ContentTypeHandshake, ctx)
	if err != nil {
		return err
	}
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s", client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[record[0]]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeFinished])))
	finished, err := protocol.ParseRecord(record, protocol.TLS_RSA_WITH_AES_128_CBC_SHA, key, iv)
	if err != nil {
		return err
	}
	recordList = append(recordList, record...)
	hash := sha1.New()
	for _, record = range ctx.RecordList {
		hash.Write(record)
	}
	finished = protocol.NewFinished(hash.Sum(nil))
	if _, err := client.Write(finished.GetRaw()); err != nil {
		return fmt.Errorf("write finished failed : %v", err)
	}
	yaklog.Debugf("%s Content Type : %s , Handshake Type : %s , Server Finished Raw : %v", mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[finished.ContentType]), comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeFinished])), finished.GetRaw())
	yaklog.Debugf(comm.SetColor(comm.RED_COLOR_TYPE, "check tls handshake finished"))
	record, err = FilterRecord(reader, protocol.ContentTypeHandshake, ctx)
	if err != nil {
		return err
	}
	return nil
}

func FilterRecord(reader *bufio.Reader, contentType uint8, args ...interface{}) ([]byte, error) {
	recordHeader := make([]byte, 5)
	if _, err := reader.Read(recordHeader); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Header from Client failed : %v", err)
	}
	if recordHeader[0] != contentType {
		return nil, ReadUnkonwnRecord(recordHeader, reader, args...)
	}
	length := binary.BigEndian.Uint16(recordHeader[3:5])
	recordFragment := make([]byte, length)
	if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read TLS Record Fragment failed : %v", err)
	}
	record := append(recordHeader, recordFragment...)
	handshakeType, ctx, err := ParseArguments(args...)
	if err != nil {
		return nil, err
	}
	switch handshakeType {
	case 0xff:
		fallthrough
	case recordFragment[0]:
		return record, nil
	default:
		return nil, ReadUnknownHandshake(record, reader, ctx)
	}
}

func ParseArguments(args ...interface{}) (uint8, *Context, error) {
	switch len(args) {
	case 0:
		return 0xff, nil, nil
	case 1:
		switch args[0].(type) {
		case uint8:
			return args[0].(uint8), nil, nil
		case *Context:
			return 0xff, args[0].(*Context), nil
		default:
			return 0xff, nil, fmt.Errorf("arguments is invaild")
		}
	case 2:
		var handshakeType uint8
		var ctx *Context
		for _, arg := range args {
			switch arg.(type) {
			case uint8:
				handshakeType = arg.(uint8)
			case *Context:
				ctx = arg.(*Context)
			default:
				return 0xff, nil, fmt.Errorf("invaild argument : %v", arg)
			}
		}
		return handshakeType, ctx, nil
	default:
		return 0xff, nil, fmt.Errorf("too many arguments")
	}
}

func ReadUnkonwnRecord(recordHeader []byte, reader *bufio.Reader, args ...interface{}) error {
	contentType := recordHeader[0]
	switch contentType {
	case protocol.ContentTypeAlert:
		length := binary.BigEndian.Uint16(recordHeader[3:5])
		recordFragment := make([]byte, length)
		if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Fragment failed : %v", err)
		}
		_, ctx, err := ParseArguments(args...)
		if err != nil {
			return err
		}
		alert, err := protocol.ParseAlert(recordFragment, ctx.Key, ctx.IV)
		if err != nil {
			return fmt.Errorf("Content Type : %s , Decrypt Alert Failed : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[protocol.ContentTypeAlert]), comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%v", err)))
		}
		return fmt.Errorf("Content Type : %s , %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.ContentType[protocol.ContentTypeAlert]), comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("[%s] %s", protocol.AlertLevel[alert.Level], protocol.AlertDescription[alert.Description])))
	case protocol.ContentTypeTLSPlaintext:
		return fmt.Errorf("TLS Record is invaild type : %s", protocol.ContentType[contentType])
	default:
		return fmt.Errorf("Content Type not supported : %v", contentType)
	}
}

func ReadUnknownHandshake(record []byte, reader *bufio.Reader, ctx *Context) error {
	//todo
	return fmt.Errorf("unknown Handshake Type")
}
