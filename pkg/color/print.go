package color

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	yaklog "github.com/yaklang/yaklang/common/log"
	"net/http"
	"net/http/httputil"
	"socks2https/setting"
)

const (
	RED_COLOR_TYPE = iota
	YELLOW_COLOR_TYPE
	BLUE_COLOR_TYPE
	GREEN_COLOR_TYPE
	WHITE_COLOR_TYPE
	MAGENTA_COLOR_TYPE

	RED_BG_COLOR_TYPE
	YELLOW_BG_COLOR_TYPE
)

var colorMap = map[int]func(arg any) aurora.Value{
	RED_COLOR_TYPE:     aurora.BrightRed,
	YELLOW_COLOR_TYPE:  aurora.BrightYellow,
	BLUE_COLOR_TYPE:    aurora.BrightBlue,
	GREEN_COLOR_TYPE:   aurora.BrightGreen,
	WHITE_COLOR_TYPE:   aurora.BrightWhite,
	MAGENTA_COLOR_TYPE: aurora.BrightMagenta,

	RED_BG_COLOR_TYPE:    aurora.BgBrightRed,
	YELLOW_BG_COLOR_TYPE: aurora.BgBrightYellow,
}

// SetColor 设置字符串颜色
func SetColor(colorType int, payload any) string {
	str := fmt.Sprintf("%v", payload)
	if setting.Config.Log.ColorSwitch {
		str = fmt.Sprint(colorMap[colorType](payload))
	}
	return str
}

// DumpRequest 打印更美观的 request 信息
func DumpRequest(req *http.Request, display bool, colorType int) {
	dump, err := httputil.DumpRequestOut(req, display)
	if err != nil {
		yaklog.Errorf("Dump Request Failed : %v", err)
		return
	}
	yaklog.Debugf("Dump Request : \n%s", SetColor(colorType, string(dump)))
}

// DumpResponse 打印更美观的 response 信息
func DumpResponse(resp *http.Response, display bool, colorType int) {
	dump, err := httputil.DumpResponse(resp, display)
	if err != nil {
		yaklog.Errorf("Dump Response Failed : %v", err)
		return
	}
	yaklog.Debugf("Dump Response : \n%s", SetColor(colorType, string(dump)))
}
