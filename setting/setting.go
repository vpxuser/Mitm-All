package setting

import (
	"github.com/kataras/golog"
	yaklog "github.com/yaklang/yaklang/common/log"
	"gopkg.in/yaml.v2"
	"os"
	"time"
)

const (
	CONFIG_PATH = "config/config.yaml"
)

var Config All

type All struct {
	Log   Log    `yaml:"log"`
	Host  string `yaml:"host"`
	Socks Socks  `yaml:"socks"`
}

type Log struct {
	Level       golog.Level `yaml:"level"`
	ColorSwitch bool        `yaml:"colorSwitch"`
}

type Socks struct {
	DebugSwitch bool     `yaml:"debugSwitch"`
	Port        string   `yaml:"port"`
	Client      Client   `yaml:"client"`
	Target      Target   `yaml:"target"`
	Proxy       []string `yaml:"proxy"`
	Bound       bool     `yaml:"bound"`
}

type Client struct {
	Timeout time.Duration `yaml:"timeout"`
}

type Target struct {
	Timeout time.Duration `yaml:"timeout"`
}

func init() {
	file, err := os.ReadFile(CONFIG_PATH)
	if err != nil {
		yaklog.Fatalf("failed to read config file ：%v", err)
	}
	// 解析 YAML 文件
	if err = yaml.Unmarshal(file, &Config); err != nil {
		yaklog.Fatalf("failed to unmarshal config file ：%v", err)
	}
}
