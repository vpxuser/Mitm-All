package setting

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/kataras/golog"
	yaklog "github.com/yaklang/yaklang/common/log"
	"gopkg.in/yaml.v3"
	"os"
	"socks2https/pkg/certutils"
	"time"
)

const (
	ConfigPath = "config/config.yaml"
)

var (
	Config Configure
	CACert *x509.Certificate
	CAKey  *rsa.PrivateKey
)

type Configure struct {
	Log   Log    `yaml:"log"`
	Socks Socks  `yaml:"socks"`
	TLS   TLS    `yaml:"tls"`
	HTTP  HTTP   `yaml:"http"`
	DNS   string `yaml:"dns"`
	CA    CA     `yaml:"ca"`
	DB    DB     `yaml:"db"`
}

type Log struct {
	ColorSwitch bool        `yaml:"colorSwitch"`
	Level       golog.Level `yaml:"level"`
}

type Socks struct {
	Host          string        `yaml:"host"`
	ClientTimeout time.Duration `yaml:"clientTimeout"`
	TargetTimeout time.Duration `yaml:"targetTimeout"`
	Bound         bool          `yaml:"bound"`
}

type TLS struct {
	VerifyFinished bool   `yaml:"verifyFinished"`
	VerifyMAC      bool   `yaml:"verifyMAC"`
	DefaultSNI     string `yaml:"defaultSNI"`
}

type HTTP struct {
	Proxy string `yaml:"proxy"`
}

type CA struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type DB struct {
	Path string `yaml:"path"`
}

func init() {
	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		yaklog.Fatalf("Read Config Failed : %v", err)
	}
	// 解析 YAML 文件
	if err = yaml.Unmarshal(file, &Config); err != nil {
		yaklog.Fatalf("Unmarshal Config Failed : %v", err)
	}
	CACert, err = certutils.LoadCert(Config.CA.Cert)
	if err != nil {
		yaklog.Fatal(err)
	}
	CAKey, err = certutils.LoadKey(Config.CA.Key)
	if err != nil {
		yaklog.Fatal(err)
	}
}
