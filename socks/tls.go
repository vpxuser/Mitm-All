package socks

import (
	"bufio"
	"encoding/binary"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
	"socks2https/pkg/protocol"
	"socks2https/setting"
	"sync"
)

func TLSMITM(reader *bufio.Reader, client net.Conn, ctx *Context) error {
	defer client.Close()
	addr := fmt.Sprintf("%s:%d", ctx.Host, ctx.Port)
	target, err := net.DialTimeout("tcp", addr, setting.TargetTimeout)
	if err != nil {
		return fmt.Errorf("connect to [%s] failed : %v", addr, err)
	}
	defer target.Close()
	wg := new(sync.WaitGroup)
	defer wg.Wait()
	wg.Add(2)
	go func() {
		defer wg.Done()
		recordLog := fmt.Sprintf("[%s ==> %s]", client.RemoteAddr().String(), target.RemoteAddr().String())
		if err = ReadTLSRecord(reader, client, target, true, ctx); err != nil {
			yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s %v", ctx.GetClientId(), recordLog, err)))
		}
	}()
	go func() {
		defer wg.Done()
		recordLog := fmt.Sprintf("[%s ==> %s]", target.RemoteAddr().String(), client.RemoteAddr().String())
		if err = ReadTLSRecord(bufio.NewReader(target), target, client, false, ctx); err != nil {
			yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s %v", ctx.GetClientId(), recordLog, err)))
		}
	}()
	return nil
}

func ReadTLSRecord(reader *bufio.Reader, src, dst net.Conn, hijackSwitch bool, ctx *Context) error {
	connectLog := fmt.Sprintf("%s [%s ==> %s]", ctx.GetClientId(), src.RemoteAddr().String(), dst.RemoteAddr().String())
	domain := ""
	for {
		recordHeader := make([]byte, 5)
		if _, err := reader.Read(recordHeader); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Header from Client failed : %v", err)
		}
		contentType := recordHeader[0]
		cType, ok := protocol.ContentType[contentType]
		if !ok {
			if _, err := reader.WriteTo(dst); err != nil {
				return fmt.Errorf("write TCP Data to Client failed : %v", err)
			}
			return fmt.Errorf("unknown TLS Record Content Type : %d", contentType)
		}
		contentLog := fmt.Sprintf("%s Content Type : %s", connectLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, cType))
		length := binary.BigEndian.Uint16(recordHeader[3:5])
		recordFragment := make([]byte, length)
		if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Fragment failed : %v", err)
		}
		record := append(recordHeader, recordFragment...)
		switch contentType {
		case protocol.ContentTypeHandshake:
			handshakeLog := fmt.Sprintf("%s , Handshake Type : ", contentLog)
			handshakeType := recordFragment[0]
			mType, ok := protocol.MessageType[handshakeType]
			if ok {
				handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, mType)))
			} else {
				handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished")))
			}
			switch handshakeType {
			case protocol.MessageTypeClientHello:
				clientHello, err := protocol.ParseTLSRecordLayer(record)
				if err != nil {
					yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%s %v", connectLog, err)))
					break
				}
				domain = clientHello.GetSNI()
				ctx.SetDomain(domain)
				yaklog.Debugf("%s , SNI : %s", handshakeLog, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))
				//todo
				ctx.SetClientHello(clientHello)
			case protocol.MessageTypeServerHello:
				serverHello, err := protocol.NewServerHello(ctx.GetClientHello())
				if err != nil {
					return err
				}
				record = serverHello.GetRaw()
				yaklog.Debugf("%s , ServerHello Length : %d", handshakeLog, serverHello.Length)
				yaklog.Debugf("%s , ServerHello Raw : %v", handshakeLog, record)
			case protocol.MessageTypeCertificate:
				domain = ctx.GetDomain()
				if domain == "" {
					break
				}
				certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
				if err != nil {
					return err
				}
				record = certificate.GetRaw()
			case protocol.MessageTypeServerHelloDone:
				record = protocol.NewServerHelloDone().GetRaw()
				//todo
			default:
				yaklog.Debugf(handshakeLog)
			}
		case protocol.ContentTypeTLSPlaintext:
			if _, err := reader.WriteTo(dst); err != nil {
				return fmt.Errorf("write TCP Data to Client failed : %v", err)
			}
			return fmt.Errorf("TLS Record is invaild type : %s", cType)
		case protocol.ContentTypeAlert:
			alert, err := protocol.ParseAlert(recordFragment)
			if err != nil {
				yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%s %v", connectLog, err)))
			} else {
				yaklog.Debugf("%s , %s", contentLog, comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("[%s] %s", protocol.AlertLevel[alert.Level], protocol.AlertDescription[alert.Description])))
			}
		default:
			yaklog.Debugf(contentLog)
		}
		if _, err := dst.Write(record); err != nil {
			return fmt.Errorf("write TLS Record failed : %v", err)
		}
		//if err := HijackTLSRecord(src, dst, record, hijackSwitch); err != nil {
		//	return err
		//}
	}
}
