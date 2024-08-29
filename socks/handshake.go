package socks

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
	"socks2https/mitm"
	"socks2https/pkg/comm"
)

const (
	SOCKS5_VERSION byte = 0x05

	// method数据包状态码
	NO_AUTHENTICATION_REQUIRED_METHOD byte = 0x00
	GSSAPI_METHOD                     byte = 0x01
	USERNAME_PASSWORD_METHOD          byte = 0x02
	NO_ACCEPTABLE_METHOD              byte = 0xff

	// username和password认证数据包状态码
	AUTHENTICATION_VERSION byte = 0x01
	SUCCESS_AUTHENTICATION byte = 0x00
	FAIL_AUTHENTICATION    byte = 0xff

	AUTHENTICATION_SWITCH bool = false
)

// socks握手处理函数
// 暂时只支持 未授权访问 方法
func Handshake(conn net.Conn, ctx *mitm.Context) error {
	// 客户端请求包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("read VER and NMETHODS failed : %v", err)
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , NMETHODS : %v", ctx.LogTamplate, ver, nMethods)
	if ver != SOCKS5_VERSION {
		return fmt.Errorf("unsupport SOCKS version : %d", ver)
	}
	methods := make([]byte, nMethods)
	if _, err := conn.Read(methods); err != nil {
		return fmt.Errorf("read METHODS failed : %v", err)
	}
	yaklog.Debugf("%s METHODS : %v", ctx.LogTamplate, methods)
	var method byte
	for _, method = range methods {
		switch method {
		case NO_AUTHENTICATION_REQUIRED_METHOD:
			break
		case USERNAME_PASSWORD_METHOD:
			if AUTHENTICATION_SWITCH {
				break
			}
			fallthrough
		default:
			method = NO_ACCEPTABLE_METHOD
		}
	}
	yaklog.Infof("%s receive Client handshake data : %s", ctx.LogTamplate, comm.SetColor(comm.GREEN_COLOR_TYPE, fmt.Sprintf("%v", append(buf, methods...))))
	// 服务端响应包
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |    1   |
	// +----+--------+
	if _, err := conn.Write([]byte{SOCKS5_VERSION, method}); err != nil {
		return fmt.Errorf("send handshake data to Client failed : %v", err)
	} else if method == NO_ACCEPTABLE_METHOD {
		return fmt.Errorf("not supported handshake methods")
	} else if AUTHENTICATION_SWITCH {
		//todo
	}
	return nil
}

//  客户端请求包
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+

func parseUnamePasswd(reader *bufio.Reader, ctx *mitm.Context) (byte, error) {
	buf := make([]byte, 2)
	if _, err := reader.Read(buf); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read VER and ULEN failed : %v", ctx.LogTamplate, err)
	}
	ver, uLen := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , ULEN : %v", ctx.LogTamplate, ver, uLen)
	if ver != AUTHENTICATION_VERSION {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s not support auth version", ctx.LogTamplate)
	}
	uname := make([]byte, uLen)
	if _, err := reader.Read(uname); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read UNAME failed : %v", ctx.LogTamplate, err)
	}
	pLen, err := reader.ReadByte()
	if err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read PLEN failed : %v", ctx.LogTamplate, err)
	}
	passwd := make([]byte, pLen)
	if _, err = reader.Read(passwd); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read PASSWD failed : %v", ctx.LogTamplate, err)
	}
	if string(passwd) == "admin" && string(uname) == "admin" {
		return SUCCESS_AUTHENTICATION, nil
	}
	return FAIL_AUTHENTICATION, nil
}

// 服务端响应包
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+

func replyUnamePass(status byte, conn net.Conn, ctx *mitm.Context) error {
	buf := []byte{AUTHENTICATION_VERSION, status}
	yaklog.Debugf("%s send auth response : %v", ctx.LogTamplate, buf)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("%s send auth response to Client failed : %v", ctx.LogTamplate, err)
	}
	return nil
}
