package tlshandler

import (
	"bufio"
	"errors"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/context"
	"socks2https/database"
	"socks2https/pkg/colorutils"
	"socks2https/pkg/tlsutils"
	"socks2https/services"
)

var ReadClientHello = TLSHandler(func(reader *bufio.Reader, conn net.Conn, ctx *context.Context) error {
	tamplate := fmt.Sprintf("%s [%s] [%s]", ctx.Client2MitmLog, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "Handshake"), colorutils.SetColor(colorutils.RED_COLOR_TYPE, "Client Hello"))
	record, err := tlsutils.FilterRecord(reader, tlsutils.ContentTypeHandshake, tlsutils.HandshakeTypeClientHello, ctx)
	if err != nil {
		//yaklog.Errorf("%s %v", tamplate, err)
		yaklog.Errorf("%s %v", ctx.Client2MitmLog, err)
		return err
	}
	ctx.TLSContext.HandshakeMessages = append(ctx.TLSContext.HandshakeMessages, record.Fragment)
	clientHello := record.Handshake.ClientHello
	ctx.TLSContext.ClientRandom = clientHello.Random
	for _, cipherSuite := range clientHello.CipherSuites {
		if cipherSuite != ctx.TLSContext.CipherSuite {
			continue
		}
		for _, extension := range clientHello.Extensions {
			if extension.Type != tlsutils.ExtensionTypeServerName {
				continue
			}
			ctx.TLSContext.SNI = extension.ServerName.List[0].Name
			yaklog.Infof("%s Domain : %s", tamplate, ctx.TLSContext.SNI)
			return nil
		}
		domain, err := services.GetDomainByIP(database.Cache, ctx.Host)
		if err != nil {
			yaklog.Infof("%s Use Default Domain : %s", tamplate, ctx.TLSContext.SNI)
			return nil
		}
		ctx.TLSContext.SNI = domain
		yaklog.Infof("%s Reverse  : %s => %s", tamplate, ctx.Host, domain)
		return nil
	}
	err = errors.New("Not Support Cipher Suites")
	yaklog.Errorf("%s %v", tamplate, err)
	return err
})
