package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"math/big"
	"net/http"
	"os"
	"socks2https/pkg/comm"
	"strings"
	"time"
)

const CertificateAndPrivateKeyPath = "config"

var (
	CertificateDB = make(map[string]*x509.Certificate)
	PrivateKeyDB  = make(map[string]*rsa.PrivateKey)
)

// GetParentDomain 获取域名的上级域名
func GetParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
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

func GetRealCertificate(domain string) (*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过证书验证，仅用于测试
			},
		},
	}
	url := fmt.Sprintf("https://%s", domain)
	yaklog.Debugf(comm.SetColor(comm.YELLOW_COLOR_TYPE, fmt.Sprintf("get Certificate from : %s", url)))
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

// CreateFakeCertificate 用于生成 MITM 证书的函数，传入 CA 证书、密钥和目标域名证书模板
func CreateFakeCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, realCert *x509.Certificate, key *rsa.PrivateKey) (*x509.Certificate, error) {
	tamplate := &x509.Certificate{
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
	certDER, err := x509.CreateCertificate(rand.Reader, tamplate, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create Fake Certificate failed : %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse Fake Certificate DER failed : %v", err)
	}
	return cert, nil
}

// IsWildcardCertificate 判断证书是否为通配符证书
func IsWildcardCertificate(cert *x509.Certificate) bool {
	if len(cert.Subject.CommonName) > 0 && cert.Subject.CommonName[0] == '*' {
		return true
	}
	for _, san := range cert.DNSNames {
		if len(san) > 0 && san[0] == '*' {
			return true
		}
	}
	return false
}

func GetKey(path, domain string) (*rsa.PrivateKey, error) {
	parentDomain := GetParentDomain(domain)
	keyDER, ok := PrivateKeyDB[domain]
	if ok {
		return keyDER, nil
	}
	keyDER, ok = PrivateKeyDB[parentDomain]
	if ok {
		return keyDER, nil
	}
	keyDER, err := LoadKey(fmt.Sprintf("%s/%s.key", path, domain))
	if err == nil {
		return keyDER, nil
	}
	keyDER, err = LoadKey(fmt.Sprintf("%s/%s.key", path, parentDomain))
	if err == nil {
		return keyDER, nil
	}
	return nil, fmt.Errorf("%s Fake Private Key not exist", domain)
}

func GetCertificate(path, domain string) (*x509.Certificate, error) {
	parentDomain := GetParentDomain(domain)
	certDER, ok := CertificateDB[domain]
	if ok {
		return certDER, nil
	}
	certDER, ok = CertificateDB[parentDomain]
	if ok {
		return certDER, nil
	}
	certDER, err := LoadCert(fmt.Sprintf("%s/%s.crt", path, domain))
	if err == nil {
		return certDER, nil
	}
	certDER, err = LoadCert(fmt.Sprintf("%s/%s.crt", path, parentDomain))
	if err == nil {
		return certDER, nil
	}
	return nil, fmt.Errorf("%s Fake Certificate not exist", domain)
}

func SaveFakeKey(path, domain string, keyDER *rsa.PrivateKey) error {
	PrivateKeyDB[domain] = keyDER
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyDER),
	}
	keyPEM, err := os.Create(fmt.Sprintf("%s/%s", path, domain))
	if err != nil {
		return fmt.Errorf("create Private Key PEM file failed : %v", err)
	}
	defer keyPEM.Close()
	if err = pem.Encode(keyPEM, block); err != nil {
		return fmt.Errorf("write Private Key PEM to file failed : %v", err)
	}
	return nil
}

func SaveCertificate(path, domain string, certDER *x509.Certificate) error {
	CertificateDB[domain] = certDER
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER.Raw,
	}
	certPEM, err := os.Create(fmt.Sprintf("%s/%s", path, domain))
	if err != nil {
		return fmt.Errorf("create Fake Certificate PEM file failed : %v", err)
	}
	defer certPEM.Close()
	err = pem.Encode(certPEM, block)
	if err != nil {
		return fmt.Errorf("write Fake Certificate PEM to file failed : %v", err)
	}
	return nil
}

func GetCertificateAndKey(path, domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	fakeCert, notExist := GetCertificate(path, domain)
	fakeKey, err := GetKey(path, domain)
	if err == nil && notExist == nil {
		return fakeCert, fakeKey, nil
	}
	realCert, err := GetRealCertificate(domain)
	if err != nil {
		return nil, nil, err
	}
	fakeKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("create Fake Private Key failed : %v", err)
	}
	caCert, err := GetCertificate(path, "ca")
	if err != nil {
		return nil, nil, err
	}
	caKey, err := GetKey(path, "ca")
	if err != nil {
		return nil, nil, err
	}
	fakeCert, err = CreateFakeCertificate(caCert, caKey, realCert, fakeKey)
	if err != nil {
		return nil, nil, err
	}
	parentDomain := GetParentDomain(domain)
	if IsWildcardCertificate(realCert) {
		if err = SaveCertificate(path, parentDomain, fakeCert); err != nil {
			return nil, nil, err
		}
		if err = SaveFakeKey(path, parentDomain, fakeKey); err != nil {
			return nil, nil, err
		}
	} else {
		if err = SaveCertificate(path, domain, fakeCert); err != nil {
			return nil, nil, err
		}
		if err = SaveFakeKey(path, domain, fakeKey); err != nil {
			return nil, nil, err
		}
	}
	return fakeCert, fakeKey, nil
}

// GetRootCAs 从文件中读取证书
func GetRootCAs(crt *x509.Certificate) (*x509.CertPool, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	})
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)
	return rootCAs, nil
}

// GenerateMITMCertificate 根据 SNI 提供的域名生成伪造的证书和私钥
func GenerateMITMCertificate(domain string, caCrt *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	// 检查输入的域名
	//if domain == "" {
	//	return nil, fmt.Errorf("domain is empty")
	//}
	// 生成 RSA 私钥
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("create private key failed : %v", err)
	}
	// 创建证书模板
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * 365 * 24 * time.Hour), // 证书有效期 1 年
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain},
	}
	// 用 CA 证书和私钥签署生成的证书
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCrt, &rsaKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate failed : %v", err)
	}
	// 编码证书和私钥为 PEM 格式
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	// 创建 tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, fmt.Errorf("create certificate failed : %v", err)
	}
	return &cert, nil
}
