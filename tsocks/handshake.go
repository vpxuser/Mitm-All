package tsocks

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
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
func handshake(tag string, conn net.Conn) error {
	// 客户端请求包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("%s read VER and NMETHODS failed : %v", tag, err)
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , NMETHODS : %v", tag, ver, nMethods)
	if ver != SOCKS5_VERSION {
		return fmt.Errorf("%s unsupport SOCKS version : %d", tag, ver)
	}
	methods := make([]byte, nMethods)
	if _, err := conn.Read(methods); err != nil {
		return fmt.Errorf("%s read METHODS failed : %v", tag, err)
	}
	yaklog.Debugf("%s METHODS : %v", tag, methods)
	var method byte
	for _, method = range methods {
		switch method {
		case NO_AUTHENTICATION_REQUIRED_METHOD:
			break
		default:
			method = NO_ACCEPTABLE_METHOD
		}
	}
	yaklog.Infof("%s receive Client handshake data : %s", tag, comm.SetColor(comm.GREEN_COLOR_TYPE, fmt.Sprintf("%v", append(buf, methods...))))
	// 服务端响应包
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |    1   |
	// +----+--------+
	if _, err := conn.Write([]byte{SOCKS5_VERSION, method}); err != nil {
		return fmt.Errorf("%s send handshake data to Client failed : %v", tag, err)
	} else if method == NO_ACCEPTABLE_METHOD {
		return fmt.Errorf("%s not supported handshake methods", tag)
	}
	return nil
}

func handshakeReader(tag string, reader *bufio.Reader, conn net.Conn) error {
	// 客户端请求包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	buf := make([]byte, 2)
	if _, err := reader.Read(buf); err != nil {
		return fmt.Errorf("%s read VER and NMETHODS failed : %v", tag, err)
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , NMETHODS : %v", tag, ver, nMethods)
	if ver != SOCKS5_VERSION {
		return fmt.Errorf("%s unsupport SOCKS version : %d", tag, ver)
	}
	methods := make([]byte, nMethods)
	if _, err := reader.Read(methods); err != nil {
		return fmt.Errorf("%s read METHODS failed : %v", tag, err)
	}
	yaklog.Debugf("%s METHODS : %v", tag, methods)
	var method byte
	for _, method = range methods {
		switch method {
		case NO_AUTHENTICATION_REQUIRED_METHOD:
			break
		default:
			method = NO_ACCEPTABLE_METHOD
		}
	}
	yaklog.Infof("%s receive Client handshake data : %s", tag, comm.SetColor(comm.GREEN_COLOR_TYPE, fmt.Sprintf("%v", append(buf, methods...))))
	// 服务端响应包
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |    1   |
	// +----+--------+
	if _, err := conn.Write([]byte{SOCKS5_VERSION, method}); err != nil {
		return fmt.Errorf("%s send handshake data to Client failed : %v", tag, err)
	} else if method == NO_ACCEPTABLE_METHOD {
		return fmt.Errorf("%s not supported handshake methods", tag)
	}
	return nil
}

func handshakeReadWriter(tag string, readWriter *bufio.ReadWriter) error {
	// 客户端请求包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	buf := make([]byte, 2)
	if _, err := readWriter.Read(buf); err != nil {
		return fmt.Errorf("%s read VER and NMETHODS failed : %v", tag, err)
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , NMETHODS : %v", tag, ver, nMethods)
	if ver != SOCKS5_VERSION {
		return fmt.Errorf("%s unsupport SOCKS version : %d", tag, ver)
	}
	methods := make([]byte, nMethods)
	if _, err := readWriter.Read(methods); err != nil {
		return fmt.Errorf("%s read METHODS failed : %v", tag, err)
	}
	yaklog.Debugf("%s METHODS : %v", tag, methods)
	var method byte
	for _, method = range methods {
		switch method {
		case NO_AUTHENTICATION_REQUIRED_METHOD:
			break
		default:
			method = NO_ACCEPTABLE_METHOD
		}
	}
	yaklog.Infof("%s receive Client handshake data : %s", tag, comm.SetColor(comm.GREEN_COLOR_TYPE, fmt.Sprintf("%v", append(buf, methods...))))
	// 服务端响应包
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |    1   |
	// +----+--------+
	if _, err := readWriter.Write([]byte{SOCKS5_VERSION, method}); err != nil {
		return fmt.Errorf("%s send handshake data to Client failed : %v", tag, err)
	} else if method == NO_ACCEPTABLE_METHOD {
		return fmt.Errorf("%s not supported handshake methods", tag)
	}
	readWriter.Flush()
	return nil
}
