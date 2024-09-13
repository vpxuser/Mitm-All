package certutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

func ForgedRootCACertificate(realCert *x509.Certificate, keyDER *rsa.PrivateKey) (*x509.Certificate, error) {
	certDER := &x509.Certificate{
		SerialNumber:          realCert.SerialNumber,       // 使用新的序列号
		Subject:               realCert.Subject,            // 复制主体信息，使其看起来与原始证书一致
		NotBefore:             time.Now(),                  // 修改有效期
		NotAfter:              time.Now().AddDate(1, 0, 0), // 证书有效期为1年
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, certDER, certDER, &keyDER.PublicKey, keyDER)
	if err != nil {
		return nil, fmt.Errorf("Failed to Create CA Certificate : %v", err)
	}
	certDER, err = x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed to Parse CA Certificate : %v", err)
	}
	return certDER, nil
}

func LoadCert(path string) (*x509.Certificate, error) {
	certRaw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Cert file failed: %v", err)
	}
	block, _ := pem.Decode(certRaw)
	if block != nil {
		certPEM, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Cert PEM failed : %v", err)
		}
		return certPEM, nil
	}
	certDER, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, fmt.Errorf("unkonwn Cert format : %v", err)
	}
	return certDER, nil
}

func LoadKey(path string) (*rsa.PrivateKey, error) {
	keyRaw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Key file failed : %v", err)
	}
	block, _ := pem.Decode(keyRaw)
	if block != nil {
		keyPEM, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse Key PEM failed : %v", err)
		}
		return keyPEM, nil
	}
	keyDER, err := x509.ParsePKCS1PrivateKey(keyRaw)
	if err != nil {
		return nil, fmt.Errorf("unknown Key format : %v", err)
	}
	return keyDER, nil
}

func GetRealCertificateWithTCP(domain string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true, // 忽略证书验证
	})
	if err != nil {
		return nil, fmt.Errorf("Connect to [%s:443] Failed : %v", domain, err)
	}
	defer conn.Close()

	// 获取证书链
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certs[0], nil
	}
	return nil, fmt.Errorf("No Certificate Exist")
}

func GetRealCertificateWithHTTPS(domain string) (*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过证书验证，仅用于测试
			},
		},
	}
	url := fmt.Sprintf("https://%s", domain)
	//yaklog.Debugf(colorutils.SetColor(colorutils.YELLOW_COLOR_TYPE, fmt.Sprintf("get Certificate from : %s", url)))
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get Certificate Template failed : %v", err)
	}
	defer resp.Body.Close()
	tlsState := resp.TLS
	if tlsState == nil {
		return nil, fmt.Errorf("no TLS Connection")
	}
	if len(tlsState.PeerCertificates) > 0 {
		return tlsState.PeerCertificates[0], nil
	}
	return nil, fmt.Errorf("no Certificate exist")
}

// ForgedCertificate 用于生成 MITM 证书的函数，传入 CA 证书、密钥和目标域名证书模板
func ForgedCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, realCert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	certDER := &x509.Certificate{
		SerialNumber:          big.NewInt(1234),            // 使用新的序列号
		Subject:               realCert.Subject,            // 复制主体信息，使其看起来与原始证书一致
		Issuer:                caCert.Subject,              // 使用传入的 CA 证书的颁发者信息
		NotBefore:             time.Now(),                  // 修改有效期
		NotAfter:              time.Now().AddDate(1, 0, 0), // 证书有效期为1年
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           realCert.ExtKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              realCert.DNSNames, // 保留原始的DNS名
	}
	certRAW, err := x509.CreateCertificate(rand.Reader, certDER, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to Forged Certificate : %v", err)
	}
	certDER, err = x509.ParseCertificate(certRAW)
	if err != nil {
		return nil, fmt.Errorf("Failed to Parse Certificate : %v", err)
	}
	return certDER, nil
}

func SaveKey(path string, keyDER *rsa.PrivateKey) error {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyDER),
	}
	keyPEM, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to Create Private Key PEM : %v", err)
	}
	defer keyPEM.Close()
	if err = pem.Encode(keyPEM, block); err != nil {
		return fmt.Errorf("Failed to Write Private Key PEM : %v", err)
	}
	return nil
}

func SaveCertificate(path string, certDER *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER.Raw,
	}
	certPEM, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to Create Certificate PEM : %v", err)
	}
	defer certPEM.Close()
	err = pem.Encode(certPEM, block)
	if err != nil {
		return fmt.Errorf("Failed to Write Certificate PEM : %v", err)
	}
	return nil
}
