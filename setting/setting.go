package setting

import (
	"flag"
	"fmt"
	"time"
)

var (
	Level         int
	NoColor       bool
	Host          string
	NoDebug       bool
	ClientTimeout time.Duration
	TargetTimeout time.Duration
	Proxy         string
	Bound         bool
)

func init() {
	// 定义命令行参数
	flag.IntVar(&Level, "level", 5, "日志级别1-5")
	flag.BoolVar(&NoColor, "noColor", false, "日志颜色开关，默认开启")
	flag.StringVar(&Host, "host", "0.0.0.0:1080", "SOCKS服务监听地址")
	flag.BoolVar(&NoDebug, "noDebug", false, "SOCKS调试开关，默认开启")
	flag.DurationVar(&ClientTimeout, "clientTimeout", 15*time.Second, "客户端连接超时设置，单位秒，默认15s")
	flag.DurationVar(&TargetTimeout, "targetTimeout", 15*time.Second, "下游代理连接超时设置，单位秒，默认15s")
	flag.StringVar(&Proxy, "proxy", "http://127.0.0.1:8081", "下游代理地址")
	flag.BoolVar(&Bound, "bound", false, "DNS解析绑定设置，默认不开启")

	// 解析命令行参数
	flag.Parse()

	// 输出调试信息
	fmt.Printf("Level:%v\n", Level)
	fmt.Printf("NoColor:%v\n", NoColor)
	fmt.Printf("Host:%v\n", Host)
	fmt.Printf("NoDebug:%v\n", NoDebug)
	fmt.Printf("ClientTimeout:%v\n", ClientTimeout)
	fmt.Printf("TargetTimeout:%v\n", TargetTimeout)
	fmt.Printf("Proxy:%v\n", Proxy)
	fmt.Printf("Bound:%v\n", Bound)
}
