package main

import (
	"fmt"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/setting"
	"socks2https/socks"
)

const PROGRAM_NAME = "\n███████╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗ ██╗  ██╗████████╗████████╗██████╗ ███████╗\n██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚════██╗██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝\n███████╗██║   ██║██║     █████╔╝ ███████╗ █████╔╝███████║   ██║      ██║   ██████╔╝███████╗\n╚════██║██║   ██║██║     ██╔═██╗ ╚════██║██╔═══╝ ██╔══██║   ██║      ██║   ██╔═══╝ ╚════██║\n███████║╚██████╔╝╚██████╗██║  ██╗███████║███████╗██║  ██║   ██║      ██║   ██║     ███████║\n╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝\n                                                                                           \n"

func init() {
	fmt.Println(PROGRAM_NAME)
	yaklog.SetLevel(setting.Config.Log.Level)
}

func main() {
	mitmSocks := socks.MITMSocks{
		Host:          setting.Config.Socks.Host,
		Proxy:         setting.Config.HTTP.Proxy,
		Threads:       setting.Config.Socks.Threads,
		ClientTimeout: setting.Config.Socks.Timeout.Client,
		TargetTimeout: setting.Config.Socks.Timeout.Target,
		DefaultSNI:    setting.Config.TLS.DefaultSNI,
	}
	mitmSocks.Run()
}
