package main

import (
	"fmt"
	"github.com/kataras/golog"
	yaklog "github.com/yaklang/yaklang/common/log"
	"socks2https/setting"
	"socks2https/socks"
	"socks2https/tsocks"
)

const PROGRAM_NAME = "\n███████╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗ ██╗  ██╗████████╗████████╗██████╗ ███████╗\n██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚════██╗██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝\n███████╗██║   ██║██║     █████╔╝ ███████╗ █████╔╝███████║   ██║      ██║   ██████╔╝███████╗\n╚════██║██║   ██║██║     ██╔═██╗ ╚════██║██╔═══╝ ██╔══██║   ██║      ██║   ██╔═══╝ ╚════██║\n███████║╚██████╔╝╚██████╗██║  ██╗███████║███████╗██║  ██║   ██║      ██║   ██║     ███████║\n╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝\n                                                                                           \n"

func init() {
	fmt.Println(PROGRAM_NAME)
	yaklog.SetLevel(golog.Level(setting.Level))
}

func main() {
	go socks.Run()
	go tsocks.Run(10800, 2, true)
	select {}
}
