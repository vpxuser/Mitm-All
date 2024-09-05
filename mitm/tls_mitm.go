package mitm

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
	"net/http"
	"socks2https/pkg/cert"
	"socks2https/pkg/comm"
	"socks2https/pkg/crypt"
	"socks2https/pkg/dns"
)

// DNS over HTTP 可能会影响中间人攻击，后续客户端连接不会传输SNI，不知道伪造证书的具体域名

type HandleRecord func(reader *bufio.Reader, conn net.Conn, ctx *Context) error

var TLSMITMPipeLine = []HandleRecord{
	ReadClientHello,
	WriteServerHello,
	WriteCertificate,
	WriteServerHelloDone,
	ReadClientKeyExchange,
	ReadChangeCipherSpec,
	ReadFinished,
	WriteChangeCipherSpec,
	WriteFinished,
	ReadApplicationData,
	WriteApplicationData,
}

func ReadUnknownRecord(record []byte, ctx *Context) (*Record, error) {
	if ctx.ClientEncrypted && record[0] != ContentTypeChangeCipherSpec {
		unkonwnRecord, err := ParseBlockRecord(record, ctx)
		if err != nil {
			return nil, err
		}
		return unkonwnRecord, nil
	} else {
		unkonwnRecord, err := ParseRecord(record, ctx)
		if err != nil {
			return nil, err
		}
		return unkonwnRecord, nil
	}
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

	record, err := ReadUnknownRecord(append(header, fragment...), ctx)
	if err != nil {
		return nil, err
	} else if record.ContentType != contentType {
		switch record.ContentType {
		case ContentTypeAlert:
			alertLevel := comm.SetColor(comm.RED_COLOR_TYPE, AlertLevel[record.Alert.Level])
			alertDescription := comm.SetColor(comm.RED_COLOR_TYPE, AlertDescription[record.Alert.Description])
			return nil, fmt.Errorf("[%s] [%s] %s", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), alertLevel, alertDescription)
		default:
			return nil, fmt.Errorf("not supported Content Type : [%v] : %d", ContentType[record.ContentType], record.ContentType)
		}
	} else if record.ContentType == ContentTypeHandshake && record.Handshake.HandshakeType != handshakeType {
		return nil, fmt.Errorf("[%s] [%s] Unknown Handshake Type : %d", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.YELLOW_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]), record.Handshake.HandshakeType)
	}
	return record, nil
}

var ReadClientHello = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, "Handshake"), comm.SetColor(comm.RED_COLOR_TYPE, "Client Hello"))
	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeClientHello, ctx)
	if err != nil {
		return err
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	clientHello := record.Handshake.ClientHello
	ctx.ClientRandom = record.Handshake.ClientHello.Random
	for _, cipherSuite := range clientHello.CipherSuites {
		if cipherSuite != ctx.CipherSuite {
			continue
		}
		for _, extension := range clientHello.Extensions {
			if extension.Type != ExtensionTypeServerName {
				continue
			}
			ctx.Domain = extension.ServerName.List[0].Name
			yaklog.Debugf("%s Domain : %s", tamplate, ctx.Domain)
			//todo
			if err = dns.DNStoIPv4(ctx.Domain, ctx.DNSServer); err != nil {
				yaklog.Warnf("%s DNS Query failed : %v", tamplate, err)
			}
			return nil
		}
		if domains, ok := cert.IPtoDomain[ctx.Host]; ok {
			ctx.Domain = domains[0]
		}
		return fmt.Errorf("%s find DNS Record failed", tamplate)
	}
	return fmt.Errorf("not support CipherSuites")
})

var WriteServerHello = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := NewServerHello(ctx)
	if err != nil {
		return err
	}
	ctx.ServerRandom = record.Handshake.ServerHello.Random
	serverHello := record.GetRaw()
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, serverHello[5:])
	if _, err = conn.Write(serverHello); err != nil {
		return err
	}
	yaklog.Debugf("%s [%s] [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	return nil
})

var WriteCertificate = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := NewCertificate(cert.CertificateAndPrivateKeyPath, ctx)
	if err != nil {
		return err
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	if _, err = conn.Write(record.GetRaw()); err != nil {
		return err
	}
	yaklog.Debugf("%s [%s] [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	return nil
})

var WriteServerHelloDone = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record := NewServerHelloDone(ctx)
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	if _, err := conn.Write(record.GetRaw()); err != nil {
		return err
	}
	yaklog.Debugf("%s [%s] [%s]", ctx.Mitm2ClientLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	return nil
})

var ReadClientKeyExchange = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeClientKeyExchange, ctx)
	if err != nil {
		return err
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	yaklog.Debugf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	clientKeyExchange := record.Handshake.ClientKeyExchange.(*RSAClientKeyExchange)
	preMasterSecret, err := crypt.DecryptRSAPKCS(ctx.KeyDER, clientKeyExchange.EncrypedPreMasterSecret)
	if err != nil {
		return err
	}
	ctx.PreMasterSecret = preMasterSecret
	//yaklog.Debugf("PreMasterSecret Length : %d , PreMasterSecret : %v", len(preMasterSecret), preMasterSecret)
	version := binary.BigEndian.Uint16(preMasterSecret[:2])
	masterSecret := PRF[version](preMasterSecret, []byte(LabelMasterSecret), append(ctx.ClientRandom[:], ctx.ServerRandom[:]...), len(preMasterSecret))
	ctx.MasterSecret = masterSecret
	//yaklog.Debugf("MasterSecret Length : %d , MasterSecret : %v", len(masterSecret), masterSecret)
	ctx.KeyBlock = PRF[version](masterSecret, []byte(LabelKeyExpansion), append(ctx.ServerRandom[:], ctx.ClientRandom[:]...), 2*(ctx.MACLength+2*ctx.BlockLength))
	//yaklog.Debugf("KeyBlock Length : %d , KeyBlock : %v", len(ctx.KeyBlock), ctx.KeyBlock)
	ctx.ClientMACKey, ctx.ServerMACKey = ctx.KeyBlock[:ctx.MACLength], ctx.KeyBlock[ctx.MACLength:2*ctx.MACLength]
	//yaklog.Debugf("ClientMACKey Length : %d , ClientMACKey : %v", len(ctx.ClientMACKey), ctx.ClientMACKey)
	//yaklog.Debugf("ServerMACKey Length : %d , ServerMACKey : %v", len(ctx.ServerMACKey), ctx.ServerMACKey)
	ctx.ClientKey, ctx.ServerKey = ctx.KeyBlock[2*ctx.MACLength:2*ctx.MACLength+ctx.BlockLength], ctx.KeyBlock[2*ctx.MACLength+ctx.BlockLength:2*(ctx.MACLength+ctx.BlockLength)]
	//yaklog.Debugf("ClientKey Length : %d , ClientKey : %v", len(ctx.ClientKey), ctx.ClientKey)
	//yaklog.Debugf("ServerKey Length : %d , ServerKey : %v", len(ctx.ServerKey), ctx.ServerKey)
	ctx.ClientIV, ctx.ServerIV = ctx.KeyBlock[2*(ctx.MACLength+ctx.BlockLength):2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength], ctx.KeyBlock[2*(ctx.MACLength+ctx.BlockLength)+ctx.BlockLength:]
	//yaklog.Debugf("ClientIV Length : %d , ClientIV : %v", len(ctx.ClientIV), ctx.ClientIV)
	//yaklog.Debugf("ServerIV Length : %d , ServerIV : %v", len(ctx.ServerIV), ctx.ServerIV)
	return nil
})

var ReadChangeCipherSpec = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := FilterRecord(reader, ContentTypeChangeCipherSpec, 0xff, ctx)
	if err != nil {
		return err
	}
	ctx.ClientEncrypted = true
	yaklog.Debugf("%s [%s] Raw : %v", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), record.Fragment)
	return err
})

var ReadFinished = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := FilterRecord(reader, ContentTypeHandshake, HandshakeTypeFinished, ctx)
	if err != nil {
		return err
	}
	tamplate := fmt.Sprintf("[%s] [%s]", comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	if ctx.VerifyFinished {
		verifyData := VerifyPRF(ctx.Version, ctx.MasterSecret, []byte(LabelClientFinished), ctx.HandshakeMessages, 12)
		if hmac.Equal(verifyData, record.Handshake.Payload) {
			yaklog.Infof("%s %s Verify Finished Successfully", ctx.Client2MitmLog, tamplate)
		} else {
			return fmt.Errorf("%s %s Verify Finished Failed", ctx.Client2MitmLog, tamplate)
		}
	} else {
		yaklog.Debugf("%s %s", ctx.Client2MitmLog, tamplate)
	}
	ctx.HandshakeMessages = append(ctx.HandshakeMessages, record.Fragment)
	//ctx.HandshakeMessages = append(ctx.HandshakeMessages, ctx.Cache)

	return nil
})

var WriteChangeCipherSpec = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record := NewChangeCipherSpec()
	if _, err := conn.Write(record.GetRaw()); err != nil {
		return err
	}
	yaklog.Debugf("%s [%s] Raw : %v", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), record.Fragment)
	return nil
})

var WriteFinished = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record := NewFinished(ctx)
	blockRecord, err := NewBlockRecord(record, ctx)
	if err != nil {
		return err
	}
	//yaklog.Debugf("blockRecord Length : %d , blockRecord : %v", len(blockRecord), blockRecord)
	if _, err := conn.Write(blockRecord); err != nil {
		return err
	}
	yaklog.Debugf("%s [%s] [%s]", ctx.Client2MitmLog, comm.SetColor(comm.YELLOW_COLOR_TYPE, ContentType[record.ContentType]), comm.SetColor(comm.RED_COLOR_TYPE, HandshakeType[record.Handshake.HandshakeType]))
	return nil
})

var ReadApplicationData = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	record, err := FilterRecord(reader, ContentTypeApplicationData, 0xff, ctx)
	if err != nil {
		return err
	}
	ctx.Request, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(record.Fragment)))
	if err != nil {
		return fmt.Errorf("read Request failed : %v", err)
	}
	ctx.Request.URL.Scheme = "https"
	ctx.Request.URL.Host = ctx.Request.Host
	ctx.Request.RequestURI = ""
	for _, modifyRequest := range ctx.RequestMITMPiPeLine {
		ctx.Request, ctx.Response = modifyRequest(ctx.Request, ctx)
	}
	return nil
})

var WriteApplicationData = HandleRecord(func(reader *bufio.Reader, conn net.Conn, ctx *Context) error {
	if ctx.Response == nil {
		var err error
		ctx.Response, err = ctx.HttpClient.Do(ctx.Request)
		if err != nil {
			return fmt.Errorf("write Request failed : %v", err)
		}
		defer ctx.Response.Body.Close()
	}
	for _, modifyResponse := range ctx.ResponseMITMPiPeLine {
		ctx.Response = modifyResponse(ctx.Response, ctx)
	}
	record, err := NewApplicationData(ctx.Response, ctx)
	if err != nil {
		return err
	}
	blockRecord, err := NewBlockRecord(record, ctx)
	if err != nil {
		return err
	}
	if _, err = conn.Write(blockRecord); err != nil {
		return fmt.Errorf("write Block Response failed : %v", err)
	}
	return nil
})

type ModifyRequest func(req *http.Request, ctx *Context) (*http.Request, *http.Response)

type ModifyResponse func(resp *http.Response, ctx *Context) *http.Response

func TLSMITM(reader *bufio.Reader, conn net.Conn, ctx *Context) {
	defer conn.Close()
	ctx.RequestMITMPiPeLine = []ModifyRequest{
		DebugRequest,
	}
	ctx.ResponseMITMPiPeLine = []ModifyResponse{
		HttpDNSResponse,
		DebugResponse,
	}
	for _, handleRecord := range TLSMITMPipeLine {
		dnsDB, _ := json.MarshalIndent(cert.IPtoDomain, "", "  ")
		yaklog.Debugf("IP to Domain : \n%s", dnsDB)
		if err := handleRecord(reader, conn, ctx); err != nil {
			yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
			return
		}
	}
}
