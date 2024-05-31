package comm

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"socks2https/setting"
)

const (
	RED_COLOR_TYPE = iota
	YELLOW_COLOR_TYPE
	BLUE_COLOR_TYPE
	GREEN_COLOR_TYPE
	WHITE_COLOR_TYPE
)

var colorMap = map[int]func(arg interface{}) aurora.Value{
	RED_COLOR_TYPE:    aurora.BrightRed,
	YELLOW_COLOR_TYPE: aurora.BgYellow,
	BLUE_COLOR_TYPE:   aurora.BrightBlue,
	GREEN_COLOR_TYPE:  aurora.BrightGreen,
	WHITE_COLOR_TYPE:  aurora.BrightWhite,
}

// SetColor 设置字符串颜色
func SetColor(colorType int, payload string) string {
	if setting.Config.Log.ColorSwitch {
		payload = fmt.Sprint(colorMap[colorType](payload))
	}
	return payload
}
