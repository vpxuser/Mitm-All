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
	"socks2https/pkg/protocol"
	"socks2https/setting"
	"sync"
)

func TLSMITM(reader *bufio.Reader, client net.Conn, addr string) error {
	defer client.Close()
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
		if err = ReadTLSRecord(reader, client, target, true); err != nil {
			yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %v", recordLog, err)))
		}
	}()
	go func() {
		defer wg.Done()
		recordLog := fmt.Sprintf("[%s ==> %s]", target.RemoteAddr().String(), client.RemoteAddr().String())
		if err = ReadTLSRecord(bufio.NewReader(target), target, client, false); err != nil {
			yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %v", recordLog, err)))
		}
	}()
	return nil
}

func ReadTLSRecord(reader *bufio.Reader, src, dst net.Conn, hijackSwitch bool) error {
	connectLog := fmt.Sprintf("[%s ==> %s]", src.RemoteAddr().String(), dst.RemoteAddr().String())
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
				yaklog.Debugf("%s , SNI : %s", handshakeLog, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))
				//todo
			case protocol.MessageTypeCertificate:
				certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
				if err != nil {
					return err
				}
				record = certificate.GetRaw()
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

func HijackTLSRecord(src, dst net.Conn, data []byte, hijackSwitch bool) error {
	if hijackSwitch {
		record, err := protocol.ParseTLSRecordLayer(data)
		if err != nil {
			return err
		}
		switch record.ContentType {
		case protocol.ContentTypeHandshake:
			switch record.TLSHandshakeMessage.MessageType {
			case protocol.MessageTypeClientHello:
				clientHello := record.TLSHandshakeMessage.ClientHello
				serverHello, err := protocol.GenrateServerHelloRaw(&clientHello)
				if err != nil {
					return err
				}
				if _, err := src.Write(serverHello); err != nil {
					return fmt.Errorf("write ServerHello failed : %v", err)
				}
			}
			fallthrough
		default:
			if _, err := dst.Write(data); err != nil {
				return fmt.Errorf("write TLS Record Header failed : %v", err)
			}
		}
	}
	return nil
}

//func HttpsMITM(hostName, addr string, reader *bufio.Reader, client net.Conn, record []byte) error {
//	if _, err := client.Write(record); err != nil {
//		return fmt.Errorf("write ServerHello to Client failed : %v", err)
//	}
//	return nil
//	//defer client.Close()
//	// 拦截客户端的 ClientHello，解析出 SNI（目标域名）
//	caCert, err := cert.GetCACertificate("config/yak.crt")
//	if err != nil {
//		return err
//	}
//	rootCAs, err := cert.GetRootCAs(caCert)
//	if err != nil {
//		return err
//	}
//	caKey, err := cert.GetCAPrivateKey("config/yak.key")
//	if err != nil {
//		return err
//	}
//	mitmCert, err := cert.GenerateMITMCertificate(hostName, caCert, caKey)
//	if err != nil {
//		return err
//	}
//
//	tlsClient := tls.Server(client, &tls.Config{
//		RootCAs:            rootCAs,
//		Certificates:       []tls.Certificate{*mitmCert},
//		InsecureSkipVerify: true,
//		ServerName:         hostName,
//	})
//	//if _, err = bytes.NewReader(record).WriteTo(tlsClient); err != nil && err != io.EOF {
//	//	return fmt.Errorf("write TLS Record to TLS Client failed : %v", err)
//	//}
//
//	if _, err = io.Copy(tlsClient, reader); err != nil {
//		return fmt.Errorf("write TLS Record to TLS Client failed : %v", err)
//	}
//
//	if err = tlsClient.Handshake(); err != nil {
//		yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("TLS Handshake failed : %v", err)))
//		return fmt.Errorf("TLS Handshake failed : %v", err)
//	}
//	req, err := http.ReadRequest(bufio.NewReader(tlsClient))
//	if err != nil {
//		yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("read Request failed : %v", err)))
//		return fmt.Errorf("read Request failed : %v", err)
//	}
//	comm.DumpRequest(req, true, comm.RED_COLOR_TYPE)
//	return nil
//}
