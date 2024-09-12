package socks

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"regexp"
	"socks2https/context"
	"socks2https/pkg/colorutils"
	"socks2https/setting"
)

const (
	HTTP_PROTOCOL  int = 0
	HTTPS_PROTOCOL int = 1
	TCP_PROTOCOL   int = 2

	CONNECT_CMD       byte = 0x01
	BIND_CMD          byte = 0x02
	UDP_ASSOCIATE_CMD byte = 0x03

	RESERVED byte = 0x00

	IPV4_ATYPE byte = 0x01
	FQDN_ATYPE byte = 0x03
	IPV6_ATYPE byte = 0x04

	SUCCEEDED_REP                    byte = 0x00
	GENERAL_SOCKS_SERVER_FAILURE_REP byte = 0x01
	CONNECTION_NOT_ALLOWED_REP       byte = 0x02
	NETWORK_UNREACHABLE_REP          byte = 0x03
	HOST_UNREACHABLE_REP             byte = 0x04
	CONNECTION_REFUSED_REP           byte = 0x05
	TTL_EXPIRED_REP                  byte = 0x06
	COMMAND_NOT_SUPPORTED_REP        byte = 0x07
	ADDRESS_TYPE_NOT_SUPPORTED_REP   byte = 0x08
)

func Runcmd(conn net.Conn, ctx *context.Context) error {
	// 客户端请求包
	// +-----+-----+-------+------+----------+----------+
	// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +-----+-----+-------+------+----------+----------+
	// |  1  |  1  | X'00' |  1   | Variable |    2     |
	// +-----+-----+-------+------+----------+----------+
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("read VER CMD RSV ATYP failed : %v", err)
	}
	ver, cmd, rsv, aTyp := buf[0], buf[1], buf[2], buf[3]
	yaklog.Debugf("%s VER : %v , CMD : %v , RSA : %v , ATYP : %v", ctx.LogTamplate, ver, cmd, rsv, aTyp)
	if ver != SOCKS5_VERSION {
		if _, err := conn.Write([]byte{SOCKS5_VERSION, GENERAL_SOCKS_SERVER_FAILURE_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return fmt.Errorf("not support socks version : %v", ver)
	} else if cmd != CONNECT_CMD {
		if _, err := conn.Write([]byte{SOCKS5_VERSION, COMMAND_NOT_SUPPORTED_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return fmt.Errorf("not support command : %v", cmd)
	} else if rsv != RESERVED {
		if _, err := conn.Write([]byte{SOCKS5_VERSION, CONNECTION_NOT_ALLOWED_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return fmt.Errorf("invail reserved : %v", rsv)
	}
	ctx.Cmd = cmd
	var host string
	var aLen byte = 0x00
	switch aTyp {
	case IPV6_ATYPE:
		buf = make([]byte, net.IPv6len)
		fallthrough
	case IPV4_ATYPE:
		if _, err := conn.Read(buf); err != nil {
			if _, err = conn.Write([]byte{SOCKS5_VERSION, GENERAL_SOCKS_SERVER_FAILURE_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
				return fmt.Errorf("write cmd to Client failed : %v", err)
			}
			return fmt.Errorf("read Target IP failed : %v", err)
		}
		host = net.IP(buf).String()
	case FQDN_ATYPE:
		if _, err := conn.Read(buf[:1]); err != nil {
			if _, err = conn.Write([]byte{SOCKS5_VERSION, GENERAL_SOCKS_SERVER_FAILURE_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
				return fmt.Errorf("write cmd to Client failed : %v", err)
			}
			return fmt.Errorf("read ALEN failed : %v", err)
		}
		aLen = buf[0]
		yaklog.Debugf("%s ALEN : %v", ctx.LogTamplate, aLen)
		if aLen > net.IPv4len {
			buf = make([]byte, aLen)
		}
		if _, err := conn.Read(buf[:aLen]); err != nil {
			if _, err = conn.Write([]byte{SOCKS5_VERSION, GENERAL_SOCKS_SERVER_FAILURE_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
				return fmt.Errorf("write cmd to Client failed : %v", err)
			}
			return fmt.Errorf("read Target FQDN failed : %v", err)
		}
		host = string(buf[:aLen])
	default:
		if _, err := conn.Write([]byte{SOCKS5_VERSION, ADDRESS_TYPE_NOT_SUPPORTED_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return fmt.Errorf("not support address type : %v", aTyp)
	}
	ctx.Host = host
	if _, err := conn.Read(buf[:2]); err != nil {
		if _, err = conn.Write([]byte{SOCKS5_VERSION, ADDRESS_TYPE_NOT_SUPPORTED_REP, RESERVED, IPV4_ATYPE, 0, 0, 0, 0, 0, 0}); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return fmt.Errorf("read Target Port failed : %v", err)
	}
	port := (uint16(buf[0]) << 8) + uint16(buf[1])
	ctx.Port = port
	addr := fmt.Sprintf("%s:%d", host, port)
	yaklog.Infof("%s Get Target Address : %s", ctx.LogTamplate, addr)

	reg := regexp.MustCompile(`:\d+$`)
	ctx.Mitm2TargetLog = fmt.Sprintf("[clientId:%s] [%s => %s] [%s]", ctx.ContextId, reg.FindString(conn.LocalAddr().String()), addr, colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
	ctx.Target2MitmLog = fmt.Sprintf("[clientId:%s] [%s => %s] [%s]", ctx.ContextId, addr, reg.FindString(conn.LocalAddr().String()), colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, "TCP"))
	// 服务端响应包
	// +-----+-----+-------+------+----------+----------+
	// | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +-----+-----+-------+------+----------+----------+
	// |  1  |  1  |   1   |   1  | Variable |    2     |
	// +-----+-----+-------+------+----------+----------+
	resp := []byte{SOCKS5_VERSION, SUCCEEDED_REP, RESERVED}
	if setting.Config.Socks.Bound {
		resp = append(resp, aTyp)
		if aLen != 0x00 {
			resp = append(resp, aLen)
		}
		if _, err := conn.Write(append(append(resp, host...), buf[:2]...)); err != nil {
			return fmt.Errorf("write cmd to Client failed : %v", err)
		}
		return nil
	}
	if _, err := conn.Write(append(resp, IPV4_ATYPE, 0, 0, 0, 0, 0, 0)); err != nil {
		return fmt.Errorf("write cmd to Client failed : %v", err)
	}
	return nil
}
