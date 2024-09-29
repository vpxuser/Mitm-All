package setting

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/kataras/golog"
	yaklog "github.com/yaklang/yaklang/common/log"
	"gopkg.in/yaml.v3"
	"os"
	"socks2https/pkg/certutils"
	"socks2https/pkg/osutils"
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
	Log  Log    `yaml:"log"`
	MITM MITM   `yaml:"mitm"`
	TLS  TLS    `yaml:"tls"`
	HTTP HTTP   `yaml:"http"`
	DNS  string `yaml:"dns"`
	CA   CA     `yaml:"ca"`
	DB   DB     `yaml:"db"`
}

type Log struct {
	ColorSwitch bool        `yaml:"colorSwitch"`
	Level       golog.Level `yaml:"level"`
}

type MITM struct {
	Host    string  `yaml:"host"`
	Threads int     `yaml:"threads"`
	Timeout Timeout `yaml:"timeout"`
	Bound   bool    `yaml:"bound"`
	Switch  bool    `yaml:"switch"`
	Dump    Dump    `yaml:"dump"`
}

type Timeout struct {
	Switch bool          `yaml:"switch"`
	Client time.Duration `yaml:"client"`
	Target time.Duration `yaml:"target"`
}

type Dump struct {
	Switch bool   `yaml:"switch"`
	Port   uint16 `yaml:"port"`
}

type TLS struct {
	MITMSwitch     bool   `yaml:"mitmSwitch"`
	VerifyFinished bool   `yaml:"verifyFinished"`
	VerifyMAC      bool   `yaml:"verifyMAC"`
	DefaultSNI     string `yaml:"defaultSNI"`
}

type HTTP struct {
	MITMSwitch bool   `yaml:"mitmSwitch"`
	Proxy      string `yaml:"proxy"`
}

type CA struct {
	Domain string `yaml:"domain"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

type DB struct {
	Cache Cache `yaml:"cache"`
	Main  Main  `yaml:"main"`
}

type Cache struct {
	LogSwitch bool `yaml:"logSwitch"`
}

type Main struct {
	LogSwitch bool   `yaml:"logSwitch"`
	Path      string `yaml:"path"`
}

func init() {
	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		yaklog.Fatalf("Read Config Failed : %v", err)
	}

	if err = yaml.Unmarshal(file, &Config); err != nil {
		yaklog.Fatalf("Unmarshal Config Failed : %v", err)
	}

	yaklog.Info("Loading Configure Successfully.")

	CAPathErr, DBPathErr := osutils.MkDir(Config.CA.Cert), osutils.MkDir(Config.DB.Main.Path)
	if CAPathErr != nil || DBPathErr != nil {
		yaklog.Fatalf("Failed to Create Dir")
	}

	CACert, CAKey, err = InitCertificateAndPrivateKey()
	if err != nil {
		yaklog.Fatal(err)
	}

	yaklog.Info("Loading Root CA Certificate and PrivateKey Successfully.")
}

func InitCertificateAndPrivateKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, certErr := certutils.LoadCert(Config.CA.Cert)
	key, keyErr := certutils.LoadKey(Config.CA.Key)
	if certErr != nil || keyErr != nil {
		key, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			return nil, nil, keyErr
		}
		defer certutils.SaveKey(Config.CA.Key, key)

		realCert, err := certutils.GetRealCertificateWithTCP(Config.CA.Domain)
		if err != nil {
			return nil, nil, err
		}

		cert, certErr = certutils.ForgedRootCACertificate(realCert, key)
		if certErr != nil {
			return nil, nil, certErr
		}
		defer certutils.SaveCertificate(Config.CA.Cert, cert)

		return cert, key, nil
	}
	return cert, key, nil
}
