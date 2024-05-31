package socks

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"io"
	"net"
)

// 客户端请求包
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// 服务端响应包
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |    1   |
// +----+--------+

const (
	SOCKS5_VERSION byte = 0x05

	NO_AUTHENTICATION_REQUIRED_METHOD byte = 0x00
	GSSAPI_METHOD                     byte = 0x01
	USERNAME_PASSWORD_METHOD          byte = 0x02
	NO_ACCEPTABLE_METHOD              byte = 0xff
)

// socks握手处理函数
// 暂时只支持 未授权访问 方法
func handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("VER : %v , NMETHODS : %v", ver, nMethods)
	if ver != SOCKS5_VERSION {
		return fmt.Errorf("not support socks version")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	yaklog.Debugf("METHODS : %v", buf)
	method := NO_ACCEPTABLE_METHOD
	for _, method = range methods {
		if method == NO_AUTHENTICATION_REQUIRED_METHOD {
			break
		}
	}
	buf = []byte{SOCKS5_VERSION, method}
	yaklog.Debugf("auth server message : %v", buf)
	_, err := conn.Write(buf)
	return err
}
