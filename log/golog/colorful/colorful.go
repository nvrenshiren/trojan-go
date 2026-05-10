// go-log库的颜色引擎
// Copyright (c) 2017 Fadhli Dzil Ikram

package colorful

import (
	"runtime"

	"github.com/p4gefau1t/trojan-go/log/golog/buffer"
)

// ColorBuffer 为缓冲区追加添加颜色选项
type ColorBuffer struct {
	buffer.Buffer
}

// color palette map
var (
	colorOff    = []byte("\033[0m")
	colorRed    = []byte("\033[0;31m")
	colorGreen  = []byte("\033[0;32m")
	colorOrange = []byte("\033[0;33m")
	colorBlue   = []byte("\033[0;34m")
	colorPurple = []byte("\033[0;35m")
	colorCyan   = []byte("\033[0;36m")
	colorGray   = []byte("\033[0;37m")
)

func init() {
	if runtime.GOOS != "linux" {
		colorOff = []byte("")
		colorRed = []byte("")
		colorGreen = []byte("")
		colorOrange = []byte("")
		colorBlue = []byte("")
		colorPurple = []byte("")
		colorCyan = []byte("")
		colorGray = []byte("")
	}
}

// Off 对数据不应用颜色
func (cb *ColorBuffer) Off() {
	cb.Append(colorOff)
}

// Red 对数据应用红色
func (cb *ColorBuffer) Red() {
	cb.Append(colorRed)
}

// Green 对数据应用绿色
func (cb *ColorBuffer) Green() {
	cb.Append(colorGreen)
}

// Orange 对数据应用橙色
func (cb *ColorBuffer) Orange() {
	cb.Append(colorOrange)
}

// Blue 对数据应用蓝色
func (cb *ColorBuffer) Blue() {
	cb.Append(colorBlue)
}

// Purple 对数据应用紫色
func (cb *ColorBuffer) Purple() {
	cb.Append(colorPurple)
}

// Cyan 对数据应用青色
func (cb *ColorBuffer) Cyan() {
	cb.Append(colorCyan)
}

// Gray 对数据应用灰色
func (cb *ColorBuffer) Gray() {
	cb.Append(colorGray)
}

// mixer 将颜色开关字节与实际数据混合
func mixer(data []byte, color []byte) []byte {
	var result []byte
	return append(append(append(result, color...), data...), colorOff...)
}

// Red 对数据应用红色
func Red(data []byte) []byte {
	return mixer(data, colorRed)
}

// Green 对数据应用绿色
func Green(data []byte) []byte {
	return mixer(data, colorGreen)
}

// Orange 对数据应用橙色
func Orange(data []byte) []byte {
	return mixer(data, colorOrange)
}

// Blue 对数据应用蓝色
func Blue(data []byte) []byte {
	return mixer(data, colorBlue)
}

// Purple 对数据应用紫色
func Purple(data []byte) []byte {
	return mixer(data, colorPurple)
}

// Cyan 对数据应用青色
func Cyan(data []byte) []byte {
	return mixer(data, colorCyan)
}

// Gray 对数据应用灰色
func Gray(data []byte) []byte {
	return mixer(data, colorGray)
}
