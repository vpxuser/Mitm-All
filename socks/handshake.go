package socks

import (
	"bufio"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net"
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
)

var (
	methodMap = map[byte]string{
		NO_AUTHENTICATION_REQUIRED_METHOD: "NO_AUTHENTICATION_REQUIRED_METHOD",
		GSSAPI_METHOD:                     "GSSAPI_METHOD",
		USERNAME_PASSWORD_METHOD:          "USERNAME_PASSWORD_METHOD",
		NO_ACCEPTABLE_METHOD:              "NO_ACCEPTABLE_METHOD",
	}

	unamepasswdMap = map[string]string{
		"admin": "admin",
	}

	supportedMethods = USERNAME_PASSWORD_METHOD
)

// socks握手处理函数
// 暂时只支持 未授权访问 方法
func handshake(tag string, reader *bufio.Reader, conn net.Conn) error {
	method, err := parseMethod(tag, reader)
	if err != nil {
		return err
	}
	if err = replyMethod(tag, method, conn); err != nil {
		return err
	}
	switch method {
	case NO_AUTHENTICATION_REQUIRED_METHOD:
		break
	case GSSAPI_METHOD:
	case USERNAME_PASSWORD_METHOD:
		status, err := parseUnamePasswd(tag, reader)
		if err != nil {
			return err
		}
		if err = replyUnamePass(tag, status, conn); err != nil {
			return err
		}
		if status != SUCCESS_AUTHENTICATION {
			_ = conn.Close()
		}
	case NO_ACCEPTABLE_METHOD:
		_ = conn.Close()
	}
	return nil
}

// 客户端请求包
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

func parseMethod(tag string, reader *bufio.Reader) (byte, error) {
	buf := make([]byte, 2)
	if _, err := reader.Read(buf); err != nil {
		return NO_ACCEPTABLE_METHOD, fmt.Errorf("%s read VER and NMETHODS failed : %v", tag, err)
	}
	ver, nMethods := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , NMETHODS : %v", tag, ver, nMethods)
	if ver != SOCKS5_VERSION {
		return NO_ACCEPTABLE_METHOD, fmt.Errorf("%s not support socks version", tag)
	}
	methods := make([]byte, nMethods)
	if _, err := reader.Read(methods); err != nil {
		return NO_ACCEPTABLE_METHOD, fmt.Errorf("%s read METHODS failed : %v", tag, err)
	}
	sMethods := make([]string, len(methods))
	for i, method := range methods {
		sMethods[i] = methodMap[method]
		if method == supportedMethods {
			yaklog.Debugf("%s METHODS : %v", tag, sMethods)
			return supportedMethods, nil
		}
	}
	yaklog.Debugf("%s METHODS : %v", tag, sMethods)
	return NO_ACCEPTABLE_METHOD, nil
}

// 服务端响应包
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |    1   |
// +----+--------+

func replyMethod(tag string, method byte, conn net.Conn) error {
	buf := []byte{SOCKS5_VERSION, method}
	yaklog.Debugf("%s send method response : %v", tag, buf)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("%s send method response to Client failed : %v", tag, err)
	}
	return nil
}

//  客户端请求包
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+

func parseUnamePasswd(tag string, reader *bufio.Reader) (byte, error) {
	buf := make([]byte, 2)
	if _, err := reader.Read(buf); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read VER and ULEN failed : %v", tag, err)
	}
	ver, uLen := buf[0], buf[1]
	yaklog.Debugf("%s VER : %v , ULEN : %v", tag, ver, uLen)
	if ver != AUTHENTICATION_VERSION {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s not support auth version", tag)
	}
	uname := make([]byte, uLen)
	if _, err := reader.Read(uname); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read UNAME failed : %v", tag, err)
	}
	pLen, err := reader.ReadByte()
	if err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read PLEN failed : %v", tag, err)
	}
	passwd := make([]byte, pLen)
	if _, err = reader.Read(passwd); err != nil {
		return FAIL_AUTHENTICATION, fmt.Errorf("%s read PASSWD failed : %v", tag, err)
	}
	if string(passwd) == unamepasswdMap[string(uname)] {
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

func replyUnamePass(tag string, status byte, conn net.Conn) error {
	buf := []byte{AUTHENTICATION_VERSION, status}
	yaklog.Debugf("%s send auth response : %v", tag, buf)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("%s send auth response to Client failed : %v", tag, err)
	}
	return nil
}
