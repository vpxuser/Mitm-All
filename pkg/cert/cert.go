package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"math/big"
	"os"
	"socks2https/pkg/comm"
	"strings"
	"time"
)

var (
	CertificateDB = make(map[string]*x509.Certificate)
	PrivateKeyDB  = make(map[string]*rsa.PrivateKey)
	SubDomainDB   = make(map[string]string)
)

func init() {
	caCertDER, noExist := LoadCert("config/ca.crt")
	caKeyDER, err := LoadKey("config/ca.key")
	if err != nil || noExist != nil {
		caKeyDER, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			yaklog.Fatalf("create CA Private Key failed : %v", err)
		} else if err = SaveFakeKey("config", "ca", caKeyDER); err != nil {
			yaklog.Fatalf("save CA Private Key failed : %v", err)
		}
		caCertDER, err = CreateFakeRootCertificate("www.digicert.com", caKeyDER)
		if err != nil {
			yaklog.Fatalf(comm.SetColor(comm.RED_COLOR_TYPE, fmt.Sprintf("%v", err)))
		} else if err = SaveCertificate("config", "ca", caCertDER); err != nil {
			yaklog.Fatalf("save CA Certificate failed : %v", err)
		}
	} else {
		CertificateDB["ca"] = caCertDER
		PrivateKeyDB["ca"] = caKeyDER
	}
}

func CreateFakeRootCertificate(domain string, caKeyDER *rsa.PrivateKey) (*x509.Certificate, error) {
	realCert, err := GetRealCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("get CA Certificate Tamplate failed : %v", err)
	}
	caTamplate := &x509.Certificate{
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
	caCertRaw, err := x509.CreateCertificate(rand.Reader, caTamplate, caTamplate, &caKeyDER.PublicKey, caKeyDER)
	if err != nil {
		return nil, fmt.Errorf("create CA Certificate failed : %v", err)
	}
	caCertDER, err := x509.ParseCertificate(caCertRaw)
	if err != nil {
		return nil, fmt.Errorf("parse CA Certificate failed : %v", err)
	}
	return caCertDER, nil
}

// GetParentDomain 获取域名的上级域名
func GetParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[1:], ".")
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

//func GetRealCertificate(domain string) (*x509.Certificate, error) {
//	client := &http.Client{
//		Transport: &http.Transport{
//			TLSClientConfig: &tls.Config{
//				InsecureSkipVerify: true, // 跳过证书验证，仅用于测试
//			},
//		},
//	}
//	url := fmt.Sprintf("https://%s", domain)
//	yaklog.Debugf(comm.SetColor(comm.YELLOW_COLOR_TYPE, fmt.Sprintf("get Certificate from : %s", url)))
//	resp, err := client.Get(url)
//	if err != nil {
//		return nil, fmt.Errorf("get Certificate Template failed : %v", err)
//	}
//	defer resp.Body.Close()
//	tlsState := resp.TLS
//	if tlsState == nil {
//		return nil, fmt.Errorf("no TLS Connection")
//	}
//	if len(tlsState.PeerCertificates) > 0 {
//		return tlsState.PeerCertificates[0], nil
//	}
//	return nil, fmt.Errorf("no Certificate exist")
//}

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
	keyPEM, err := os.Create(fmt.Sprintf("%s/%s.key", path, domain))
	if err != nil && !os.IsExist(err) && domain != "ca" {
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
	certPEM, err := os.Create(fmt.Sprintf("%s/%s.crt", path, domain))
	if err != nil && !os.IsExist(err) && domain != "ca" {
		return fmt.Errorf("create Fake Certificate PEM file failed : %v", err)
	}
	defer certPEM.Close()
	err = pem.Encode(certPEM, block)
	if err != nil {
		return fmt.Errorf("write Fake Certificate PEM to file failed : %v", err)
	}
	return nil
}

// todo 通配符域名bug修复
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
