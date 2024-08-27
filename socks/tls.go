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
	"socks2https/pkg/crypt"
	"socks2https/pkg/protocol"
	"socks2https/setting"
)

func TLSMITM(reader *bufio.Reader, client net.Conn, ctx *Context) error {
	defer client.Close()
	addr := fmt.Sprintf("%s:%d", ctx.Host, ctx.Port)
	target, err := net.DialTimeout("tcp", addr, setting.TargetTimeout)
	if err != nil {
		return fmt.Errorf("connect to [%s] failed : %v", addr, err)
	}
	defer target.Close()
	recordLog := fmt.Sprintf("[%s ==> %s]", client.RemoteAddr().String(), target.RemoteAddr().String())
	if err = ReadTLSRecordV2(reader, client, ctx); err != nil {
		yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s %v", ctx.GetClientId(), recordLog, err)))
	}

	//wg := new(sync.WaitGroup)
	//defer wg.Wait()
	//wg.Add(2)
	//go func() {
	//	defer wg.Done()
	//	recordLog := fmt.Sprintf("[%s ==> %s]", client.RemoteAddr().String(), target.RemoteAddr().String())
	//	if err = ReadTLSRecord(reader, client, target, true, ctx); err != nil {
	//		yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s %v", ctx.GetClientId(), recordLog, err)))
	//	}
	//}()
	//go func() {
	//	defer wg.Done()
	//	recordLog := fmt.Sprintf("[%s ==> %s]", target.RemoteAddr().String(), client.RemoteAddr().String())
	//	if err = ReadTLSRecord(bufio.NewReader(target), target, client, false, ctx); err != nil {
	//		yaklog.Errorf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%s %s %v", ctx.GetClientId(), recordLog, err)))
	//	}
	//}()
	return nil
}

func ReadTLSRecordV2(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	clientId := ctx.GetClientId()
	client2MitmLog := fmt.Sprintf("%s [%s ==> %s]", clientId, conn.RemoteAddr().String(), conn.LocalAddr().String())
	mitm2ClientLog := fmt.Sprintf("%s [%s ==> %s]", clientId, conn.LocalAddr().String(), conn.RemoteAddr().String())
	domain := ""
	for {
		recordHeader := make([]byte, 5)
		if _, err := reader.Read(recordHeader); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Header from Client failed : %v", err)
		}
		contentType := recordHeader[0]
		cType, ok := protocol.ContentType[contentType]
		if !ok {
			return fmt.Errorf("unknown TLS Record Content Type : %d", contentType)
		}
		contentLog := fmt.Sprintf("Content Type : %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, cType))
		length := binary.BigEndian.Uint16(recordHeader[3:5])
		recordFragment := make([]byte, length)
		if _, err := reader.Read(recordFragment); err != nil && err != io.EOF {
			return fmt.Errorf("read TLS Record Fragment failed : %v", err)
		}
		record := append(recordHeader, recordFragment...)
		switch contentType {
		case protocol.ContentTypeHandshake:
			handshakeLog := fmt.Sprintf("Handshake Type :")
			handshakeType := recordFragment[0]
			if _, ok := protocol.HandshakeType[handshakeType]; !ok {
				if ctx.Encrypted {
					finished, err := protocol.ParseRecord(record, protocol.TLS_RSA_WITH_AES_128_CBC_SHA)
					if err != nil {
						return err
					}
					verifyData := finished.Handshake.Finished.(*protocol.AES128CBCFinished).VerifyData
					iv := finished.Handshake.Finished.(*protocol.AES128CBCFinished).IV
					plainData, err := crypt.DecryptAES128CBCPKCS7(ctx.Secret, verifyData, iv[:])
					if err != nil {
						return err
					}
					yaklog.Debugf("%s %s , %s %s , VerifyData : %v", client2MitmLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished")), plainData)
				}
				yaklog.Warnf("%s Unknown Handshake Type : %d", client2MitmLog, handshakeType)
			}
			switch handshakeType {
			case protocol.HandshakeTypeClientHello:
				clientHello, err := protocol.ParseRecord(record)
				if err != nil {
					return err
				}
				domain, ok = clientHello.GetDomain()
				if ok {
					yaklog.Debugf("%s %s , %s %s , SNI : %s", client2MitmLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeClientHello])), comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))
				} else {
					return fmt.Errorf("domain is empty")
				}
				serverHello, err := protocol.NewServerHello(clientHello)
				if err != nil {
					return err
				}
				record = serverHello.GetRaw()
				yaklog.Debugf("%s %s , %s %s , ServerHello Length : %d , ServerHello Raw : %v", mitm2ClientLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeServerHello])), serverHello.Length, record)
				if _, err = conn.Write(record); err != nil {
					return fmt.Errorf("write TLS Record failed : %v", err)
				}
				certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
				if err != nil {
					return err
				}
				record = certificate.GetRaw()
				yaklog.Debugf("%s %s , %s %s , Certificate Length : %d , Certificate Raw : %v", mitm2ClientLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeCertificate])), certificate.Length, record)
				if _, err = conn.Write(record); err != nil {
					return fmt.Errorf("write TLS Record failed : %v", err)
				}
				serverHelloDone := protocol.NewServerHelloDone()
				record = serverHelloDone.GetRaw()
				yaklog.Debugf("%s %s , %s %s , ServerHelloDone Length : %d , ServerHelloDone Raw : %v", mitm2ClientLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeServerHelloDone])), serverHelloDone.Handshake.Length, record)
				if _, err = conn.Write(record); err != nil {
					return fmt.Errorf("write TLS Record failed : %v", err)
				}
			case protocol.HandshakeTypeClientKeyExchange:
				clientKeyExchange, err := protocol.ParseRecord(record, protocol.KeyExchangeRSA)
				if err != nil {
					return err
				}
				//todo
				encryptedSecret := clientKeyExchange.Handshake.ClientKeyExchange.(*protocol.ClientKeyExchangeRSA).EncryptedPreMasterSecret
				_, privateKey, err := cert.GetCertificateAndKey("config", "ca")
				if err != nil {
					return err
				}
				secret, err := crypt.PKCS1RSADecrypt(privateKey, encryptedSecret)
				if err != nil {
					return err
				}
				yaklog.Debugf("%s %s , %s%s , PreMaster Secret : %v", client2MitmLog, contentLog, handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeClientKeyExchange])), secret)
			default:
				yaklog.Debugf(handshakeLog)
			}
		case protocol.ContentTypeChangeCipherSpec:
			ctx.Encrypted = true
			yaklog.Debugf("%s %s", client2MitmLog, contentLog)
		case protocol.ContentTypeTLSPlaintext:
			return fmt.Errorf("TLS Record is invaild type : %s", cType)
		case protocol.ContentTypeAlert:
			alert, err := protocol.ParseAlert(recordFragment)
			if err != nil {
				yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%s %s %v", client2MitmLog, contentLog, err)))
			} else {
				yaklog.Debugf("%s %s , %s", client2MitmLog, contentLog, comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("[%s] %s", protocol.AlertLevel[alert.Level], protocol.AlertDescription[alert.Description])))
			}
		default:
			yaklog.Debugf("%s %s", client2MitmLog, contentLog)
		}
	}
}

func ReadTLSRecord(reader *bufio.Reader, src, dst net.Conn, hijackSwitch bool, ctx *Context) error {
	connectLog := ctx.GetClientId()
	if hijackSwitch {
		connectLog = fmt.Sprintf("%s [%s ==> %s]", connectLog, src.RemoteAddr().String(), src.RemoteAddr().String())
	} else {
		connectLog = fmt.Sprintf("%s [%s ==> %s]", connectLog, src.RemoteAddr().String(), dst.RemoteAddr().String())
	}
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
		if hijackSwitch {
			if _, err := dst.Write(record); err != nil {
				return fmt.Errorf("write TLS Record failed : %v", err)
			}
		}
		switch contentType {
		case protocol.ContentTypeHandshake:
			handshakeLog := fmt.Sprintf("%s , Handshake Type : ", contentLog)
			handshakeType := recordFragment[0]
			mType, ok := protocol.HandshakeType[handshakeType]
			if ok {
				handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, mType)))
			} else {
				handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Finished")))
			}
			switch handshakeType {
			case protocol.HandshakeTypeClientHello:
				clientHello, err := protocol.ParseRecord(record)
				if err != nil {
					yaklog.Warnf(comm.SetColor(comm.MAGENTA_COLOR_TYPE, fmt.Sprintf("%s %v", connectLog, err)))
					break
				}
				domain, ok = clientHello.GetDomain()
				if ok {
					yaklog.Debugf("%s , SNI : %s", handshakeLog, comm.SetColor(comm.YELLOW_BG_COLOR_TYPE, comm.SetColor(comm.RED_COLOR_TYPE, domain)))
				}
				ctx.SetDomain(domain)
				//todo
				if hijackSwitch {
					serverHello, err := protocol.NewServerHello(ctx.GetClientHello())
					if err != nil {
						return err
					}
					record = serverHello.GetRaw()
					handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeServerHello])))
					yaklog.Debugf("%s , ServerHello Length : %d , ServerHello Raw : %v", handshakeLog, serverHello.Length, record)
					if _, err = src.Write(record); err != nil {
						return fmt.Errorf("write TLS Record failed : %v", err)
					}
					domain = ctx.GetDomain()
					if domain == "" {
						break
					}
					certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
					if err != nil {
						return err
					}
					record = certificate.GetRaw()
					handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeCertificate])))
					yaklog.Debugf("%s , Certificate Length : %d , Certificate Raw : %v", handshakeLog, certificate.Length, record)
					if _, err = src.Write(record); err != nil {
						return fmt.Errorf("write TLS Record failed : %v", err)
					}
					serverHelloDone := protocol.NewServerHelloDone()
					record = serverHelloDone.GetRaw()
					handshakeLog = fmt.Sprintf("%s%s", handshakeLog, comm.SetColor(comm.RED_BG_COLOR_TYPE, comm.SetColor(comm.YELLOW_COLOR_TYPE, protocol.HandshakeType[protocol.HandshakeTypeServerHelloDone])))
					yaklog.Debugf("%s , ServerHelloDone Length : %d , ServerHelloDone Raw : %v", handshakeLog, serverHelloDone.Handshake.Length, record)
					if _, err = src.Write(record); err != nil {
						return fmt.Errorf("write TLS Record failed : %v", err)
					}
				}

				//ctx.SetClientHello(clientHello)
			//case protocol.HandshakeTypeServerHello:
			//	serverHello, err := protocol.NewServerHello(ctx.GetClientHello())
			//	if err != nil {
			//		return err
			//	}
			//	record = serverHello.GetRaw()
			//	yaklog.Debugf("%s , ServerHello Length : %d , ServerHello Raw : %v", handshakeLog, serverHello.Length, record)
			//case protocol.HandshakeTypeServerKeyExchange:
			//	yaklog.Debugf(handshakeLog)
			//	continue
			//case protocol.HandshakeTypeCertificate:
			//	domain = ctx.GetDomain()
			//	if domain == "" {
			//		break
			//	}
			//	certificate, err := protocol.NewCertificate(cert.CertificateAndPrivateKeyPath, domain)
			//	if err != nil {
			//		return err
			//	}
			//	record = certificate.GetRaw()
			//	yaklog.Debugf("%s , Certificate Length : %d , Certificate Raw : %v", handshakeLog, certificate.Length, record)
			//case protocol.HandshakeTypeServerHelloDone:
			//	serverHelloDone := protocol.NewServerHelloDone()
			//	record = serverHelloDone.GetRaw()
			//	yaklog.Debugf("%s , ServerHelloDone Length : %d , ServerHelloDone Raw : %v", handshakeLog, serverHelloDone.Handshake.Length, record)
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
		if !hijackSwitch {
			if _, err := dst.Write(record); err != nil {
				return fmt.Errorf("write TLS Record failed : %v", err)
			}
		}
	}
}
