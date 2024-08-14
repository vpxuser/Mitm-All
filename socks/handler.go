package socks

import (
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
)

func handler(tag string, client net.Conn) {
	defer func() {
		if err := client.Close(); err != nil {
			yaklog.Errorf("%s Client close failed : %v", tag, err)
		}
	}()
	if err := handshake(tag, client); err != nil {
		yaklog.Error(err)
		return
	}
	yaklog.Infof("%s Client finish socks handshake", tag)
	server, protocol, rep, err := connect(tag, client)
	if err != nil || server == nil {
		yaklog.Error(err)
		if err = failure(tag, client, rep); err == nil {
			yaklog.Warn(err)
		}
		return
	}
	defer func() {
		if err = server.Close(); err != nil {
			yaklog.Errorf("%s Server close failed : %v", tag, err)
		}
	}()
	if err = success(tag, client); err != nil {
		yaklog.Warn(err)
	}
	yaklog.Infof("%s Client connect to Target", tag)

	//todo
	//p, err := parseProtocol(tag, client)
	//if err != nil {
	//	yaklog.Error(err)
	//}
	//yaklog.Infof("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("Protocol is %s", protocolList[p])))
	//todo

	if err = forward(tag, protocol, client, server); err != nil {
		yaklog.Error(err)
	}
	yaklog.Infof("%s Client send message to Target fisished", tag)
}

var protocolList = []string{
	"HTTP",
	"HTTPS",
	"TCP",
}

//func parseProtocol(tag string, client net.Conn) (int, error) {
//	reader := bufio.NewReader(client)
//	protocolHeader, err := reader.Peek(3)
//	if err != nil {
//		return -1, fmt.Errorf("%s pre read ProtocolHeader failed : %v", tag, err)
//	}
//	yaklog.Debugf("%s %s", tag, comm.SetColor(comm.RED_COLOR_TYPE, string(protocolHeader)))
//	switch string(protocolHeader) {
//	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "TRA", "CON":
//		return HTTP_PROTOCOL, nil
//	default:
//		return TCP_PROTOCOL, nil
//	}
//}
