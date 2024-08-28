package protocol

import (
	"fmt"
	"socks2https/pkg/crypt"
)

// 定义TLS Alert级别常量
const (
	AlertLevelWarning uint8 = 1 // 警告级别
	AlertLevelFatal   uint8 = 2 // 严重错误级别
)

// 定义TLS Alert描述常量
const (
	AlertDescriptionCloseNotify            uint8 = 0   // 关闭通知
	AlertDescriptionUnexpectedMessage      uint8 = 10  // 意外的消息
	AlertDescriptionBadRecordMAC           uint8 = 20  // 错误的记录MAC
	AlertDescriptionDecryptionFailed       uint8 = 21  // 解密失败 (仅TLS 1.0)
	AlertDescriptionRecordOverflow         uint8 = 22  // 记录溢出
	AlertDescriptionDecompressionFailure   uint8 = 30  // 解压失败
	AlertDescriptionHandshakeFailure       uint8 = 40  // 握手失败
	AlertDescriptionNoCertificate          uint8 = 41  // 没有证书 (SSL 3.0)
	AlertDescriptionBadCertificate         uint8 = 42  // 错误的证书
	AlertDescriptionUnsupportedCertificate uint8 = 43  // 不支持的证书
	AlertDescriptionCertificateRevoked     uint8 = 44  // 证书被撤销
	AlertDescriptionCertificateExpired     uint8 = 45  // 证书已过期
	AlertDescriptionCertificateUnknown     uint8 = 46  // 未知证书
	AlertDescriptionIllegalParameter       uint8 = 47  // 非法参数
	AlertDescriptionUnknownCA              uint8 = 48  // 未知的CA
	AlertDescriptionAccessDenied           uint8 = 49  // 访问被拒绝
	AlertDescriptionDecodeError            uint8 = 50  // 解码错误
	AlertDescriptionDecryptError           uint8 = 51  // 解密错误
	AlertDescriptionProtocolVersion        uint8 = 70  // 协议版本错误
	AlertDescriptionInsufficientSecurity   uint8 = 71  // 安全级别不足 (TLS 1.2)
	AlertDescriptionInternalError          uint8 = 80  // 内部错误
	AlertDescriptionInappropriateFallback  uint8 = 86  // 不适当的回退 (TLS 1.3)
	AlertDescriptionUserCanceled           uint8 = 90  // 用户取消
	AlertDescriptionNoRenegotiation        uint8 = 100 // 不允许重新协商
	AlertDescriptionMissingExtension       uint8 = 109 // 缺少扩展 (TLS 1.3)
	AlertDescriptionUnsupportedExtension   uint8 = 110 // 不支持的扩展
	AlertDescriptionCertificateRequired    uint8 = 116 // 需要证书 (TLS 1.3)
	AlertDescriptionNoApplicationProtocol  uint8 = 120 // 没有应用层协议 (TLS 1.3)
)

var AlertLevel = map[uint8]string{
	AlertLevelWarning: "WARNING",
	AlertLevelFatal:   "FATAL",
}

var AlertDescription = map[uint8]string{
	AlertDescriptionCloseNotify:            "Close Notify",
	AlertDescriptionUnexpectedMessage:      "Unexpected Message",
	AlertDescriptionBadRecordMAC:           "Bad Record MAC",
	AlertDescriptionDecryptionFailed:       "Decryption Failed",
	AlertDescriptionRecordOverflow:         "Record Overflow",
	AlertDescriptionDecompressionFailure:   "Decompression Failure",
	AlertDescriptionHandshakeFailure:       "Handshake Failure",
	AlertDescriptionNoCertificate:          "No Certificate",
	AlertDescriptionBadCertificate:         "Bad Certificate",
	AlertDescriptionUnsupportedCertificate: "Unsupported Certificate",
	AlertDescriptionCertificateRevoked:     "Certificate Revoked",
	AlertDescriptionCertificateExpired:     "Certificate Expired",
	AlertDescriptionCertificateUnknown:     "Certificate Unknown",
	AlertDescriptionIllegalParameter:       "Illegal Parameter",
	AlertDescriptionUnknownCA:              "Unknown CA",
	AlertDescriptionAccessDenied:           "Access Denied",
	AlertDescriptionDecodeError:            "Decode Error",
	AlertDescriptionDecryptError:           "Decrypt Error",
	AlertDescriptionProtocolVersion:        "Protocol Version",
	AlertDescriptionInsufficientSecurity:   "Insufficient Security",
	AlertDescriptionInternalError:          "Internal Error",
	AlertDescriptionInappropriateFallback:  "Inappropriate Fallback",
	AlertDescriptionUserCanceled:           "User Canceled",
	AlertDescriptionNoRenegotiation:        "No Renegotiation",
	AlertDescriptionMissingExtension:       "Missing Extension",
	AlertDescriptionUnsupportedExtension:   "Unsupported Extension",
	AlertDescriptionCertificateRequired:    "Certificate Required",
	AlertDescriptionNoApplicationProtocol:  "No Application Protocol",
}

type Alert struct {
	Level       uint8 // 告警级别
	Description uint8 // 告警描述
}

func ParseAlert(data []byte, args ...interface{}) (*Alert, error) {
	if len(data) == 2 {
		return &Alert{Level: data[0], Description: data[1]}, nil
	}
	//maybe encrypted alert
	key, ok := args[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("get AES Key failed")
	}
	iv, ok := args[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("get AES IV failed")
	}
	fragment, err := crypt.DecryptAESCBC(data, key, iv)
	if err != nil {
		return nil, err
	}
	return &Alert{Level: fragment[0], Description: fragment[1]}, nil
}
