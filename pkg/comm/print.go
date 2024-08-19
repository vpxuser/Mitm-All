package comm

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
	RED_BG_COLOR_TYPE
	YELLOW_BG_COLOR_TYPE
)

var colorMap = map[int]func(arg interface{}) aurora.Value{
	RED_COLOR_TYPE:    aurora.BrightRed,
	YELLOW_COLOR_TYPE: aurora.BrightYellow,
	BLUE_COLOR_TYPE:   aurora.BrightBlue,
	GREEN_COLOR_TYPE:  aurora.BrightGreen,
	WHITE_COLOR_TYPE:  aurora.BrightWhite,

	RED_BG_COLOR_TYPE:    aurora.BgBrightRed,
	YELLOW_BG_COLOR_TYPE: aurora.BgBrightYellow,
}

// SetColor 设置字符串颜色
func SetColor(colorType int, payload string) string {
	if !setting.NoColor {
		payload = fmt.Sprint(colorMap[colorType](payload))
	}
	return payload
}

// DumpRequest 打印更美观的 request 信息
func DumpRequest(req *http.Request, displayBody bool, colorType int) {
	dump, err := httputil.DumpRequest(req, displayBody)
	if err != nil {
		yaklog.Errorf("dump request failed : %v", err)
		return
	}
	yaklog.Debugf("dump request : \n%s", SetColor(colorType, string(dump)))
}

// DumpResponse 打印更美观的 response 信息
func DumpResponse(resp *http.Response, displayBody bool, colorType int) {
	dump, err := httputil.DumpResponse(resp, displayBody)
	if err != nil {
		yaklog.Errorf("dump response failed : %v", err)
		return
	}
	yaklog.Debugf("dump response : \n%s", SetColor(colorType, string(dump)))
}
