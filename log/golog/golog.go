// 彩色简洁的日志库
// Copyright (c) 2017 Fadhli Dzil Ikram

package golog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	terminal "golang.org/x/term"

	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/log/golog/colorful"
)

func init() {
	log.RegisterLogger(New(os.Stdout))
}

// FdWriter 接口扩展现有的io.Writer以支持文件描述符函数
// 支持
type FdWriter interface {
	io.Writer
	Fd() uintptr
}

// Logger 结构体定义单个日志记录器的底层存储
type Logger struct {
	mu        sync.RWMutex
	color     bool
	out       io.Writer
	debug     bool
	timestamp bool
	quiet     bool
	buf       colorful.ColorBuffer
	logLevel  int32
}

// Prefix 结构体定义纯文本和颜色的字节
type Prefix struct {
	Plain []byte
	Color []byte
	File  bool
}

var (
	// 纯文本前缀模板
	plainFatal = []byte("[FATAL] ")
	plainError = []byte("[ERROR] ")
	plainWarn  = []byte("[WARN]  ")
	plainInfo  = []byte("[INFO]  ")
	plainDebug = []byte("[DEBUG] ")
	plainTrace = []byte("[TRACE] ")

	// FatalPrefix 显示致命前缀
	FatalPrefix = Prefix{
		Plain: plainFatal,
		Color: colorful.Red(plainFatal),
		File:  true,
	}

	// ErrorPrefix 显示错误前缀
	ErrorPrefix = Prefix{
		Plain: plainError,
		Color: colorful.Red(plainError),
		File:  true,
	}

	// WarnPrefix 显示警告前缀
	WarnPrefix = Prefix{
		Plain: plainWarn,
		Color: colorful.Orange(plainWarn),
	}

	// InfoPrefix 显示信息前缀
	InfoPrefix = Prefix{
		Plain: plainInfo,
		Color: colorful.Green(plainInfo),
	}

	// DebugPrefix 显示调试前缀
	DebugPrefix = Prefix{
		Plain: plainDebug,
		Color: colorful.Purple(plainDebug),
		File:  true,
	}

	// TracePrefix 显示跟踪前缀
	TracePrefix = Prefix{
		Plain: plainTrace,
		Color: colorful.Cyan(plainTrace),
	}
)

// New 返回一个新的Logger实例，使用预定义的writer输出并自动检测终端颜色支持
func New(out FdWriter) *Logger {
	return &Logger{
		color:     terminal.IsTerminal(int(out.Fd())),
		out:       out,
		timestamp: true,
	}
}

func (l *Logger) SetLogLevel(level log.LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	atomic.StoreInt32(&l.logLevel, int32(level))
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = false
	if fdw, ok := w.(FdWriter); ok {
		l.color = terminal.IsTerminal(int(fdw.Fd()))
	}
	l.out = w
}

// WithColor 明确开启日志的彩色功能
func (l *Logger) WithColor() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = true
	return l
}

// WithoutColor 明确关闭日志的彩色功能
func (l *Logger) WithoutColor() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.color = false
	return l
}

// WithDebug 开启日志的调试输出以显示debug和trace级别
func (l *Logger) WithDebug() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = true
	return l
}

// WithoutDebug 关闭日志的调试输出
func (l *Logger) WithoutDebug() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = false
	return l
}

// IsDebug 检查调试输出的状态
func (l *Logger) IsDebug() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.debug
}

// WithTimestamp 开启日志的时间戳输出
func (l *Logger) WithTimestamp() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.timestamp = true
	return l
}

// WithoutTimestamp 关闭日志的时间戳输出
func (l *Logger) WithoutTimestamp() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.timestamp = false
	return l
}

// Quiet 关闭所有日志输出
func (l *Logger) Quiet() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiet = true
	return l
}

// NoQuiet 开启所有日志输出
func (l *Logger) NoQuiet() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiet = false
	return l
}

// IsQuiet 检查安静状态
func (l *Logger) IsQuiet() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.quiet
}

// Output 打印实际的值
func (l *Logger) Output(depth int, prefix Prefix, data string) error {
	// 检查是否请求了安静模式，并尝试返回无错误并保持安静
	if l.IsQuiet() {
		return nil
	}
	// 获取当前时间
	now := time.Now()
	// 用于文件和行追踪的临时存储
	var file string
	var line int
	var fn string
	// 检查指定的前缀是否需要包含在文件日志中
	if prefix.File {
		var ok bool
		var pc uintptr

		// 获取调用者的文件名和行号
		if pc, file, line, ok = runtime.Caller(depth + 2); !ok {
			file = "<unknown file>"
			fn = "<unknown function>"
			line = 0
		} else {
			file = filepath.Base(file)
			fn = runtime.FuncForPC(pc).Name()
		}
	}
	// 获取共享缓冲区的独占访问权
	l.mu.Lock()
	defer l.mu.Unlock()
	// 重置缓冲区使其从头开始
	l.buf.Reset()
	// 将前缀写入缓冲区
	if l.color {
		l.buf.Append(prefix.Color)
	} else {
		l.buf.Append(prefix.Plain)
	}
	// 检查日志是否需要时间戳
	if l.timestamp {
		// 如果启用颜色则打印时间戳颜色
		if l.color {
			l.buf.Blue()
		}
		// 打印日期和时间
		year, month, day := now.Date()
		l.buf.AppendInt(year, 4)
		l.buf.AppendByte('/')
		l.buf.AppendInt(int(month), 2)
		l.buf.AppendByte('/')
		l.buf.AppendInt(day, 2)
		l.buf.AppendByte(' ')
		hour, min, sec := now.Clock()
		l.buf.AppendInt(hour, 2)
		l.buf.AppendByte(':')
		l.buf.AppendInt(min, 2)
		l.buf.AppendByte(':')
		l.buf.AppendInt(sec, 2)
		l.buf.AppendByte(' ')
		// 如果启用颜色则打印重置颜色
		if l.color {
			l.buf.Off()
		}
	}
	// 如果启用则添加调用者文件名和行号
	if prefix.File {
		// 如果启用则打印颜色开始
		if l.color {
			l.buf.Orange()
		}
		// 打印文件名和行号
		l.buf.Append([]byte(fn))
		l.buf.AppendByte(':')
		l.buf.Append([]byte(file))
		l.buf.AppendByte(':')
		l.buf.AppendInt(line, 0)
		l.buf.AppendByte(' ')
		// 打印颜色停止
		if l.color {
			l.buf.Off()
		}
	}
	// 打印来自调用者的实际字符串数据
	l.buf.Append([]byte(data))
	if len(data) == 0 || data[len(data)-1] != '\n' {
		l.buf.AppendByte('\n')
	}
	// 将缓冲区刷新到输出
	_, err := l.out.Write(l.buf.Buffer)
	return err
}

// Fatal 打印致命消息到输出并以状态1退出应用程序
func (l *Logger) Fatal(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 4 {
		l.Output(1, FatalPrefix, fmt.Sprintln(v...))
	}
	os.Exit(1)
}

// Fatalf 打印格式化致命消息到输出并以状态1退出应用程序
func (l *Logger) Fatalf(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 4 {
		l.Output(1, FatalPrefix, fmt.Sprintf(format, v...))
	}
	os.Exit(1)
}

// Error 打印错误消息到输出
func (l *Logger) Error(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 3 {
		l.Output(1, ErrorPrefix, fmt.Sprintln(v...))
	}
}

// Errorf 打印格式化错误消息到输出
func (l *Logger) Errorf(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 3 {
		l.Output(1, ErrorPrefix, fmt.Sprintf(format, v...))
	}
}

// Warn 打印警告消息到输出
func (l *Logger) Warn(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 2 {
		l.Output(1, WarnPrefix, fmt.Sprintln(v...))
	}
}

// Warnf 打印格式化警告消息到输出
func (l *Logger) Warnf(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 2 {
		l.Output(1, WarnPrefix, fmt.Sprintf(format, v...))
	}
}

// Info 打印信息性消息到输出
func (l *Logger) Info(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 1 {
		l.Output(1, InfoPrefix, fmt.Sprintln(v...))
	}
}

// Infof 打印格式化信息性消息到输出
func (l *Logger) Infof(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) <= 1 {
		l.Output(1, InfoPrefix, fmt.Sprintf(format, v...))
	}
}

// Debug 如果启用调试输出则打印调试消息到输出
func (l *Logger) Debug(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) == 0 {
		l.Output(1, DebugPrefix, fmt.Sprintln(v...))
	}
}

// Debugf 如果启用调试输出则打印格式化调试消息到输出
func (l *Logger) Debugf(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) == 0 {
		l.Output(1, DebugPrefix, fmt.Sprintf(format, v...))
	}
}

// Trace 如果启用调试输出则打印跟踪消息到输出
func (l *Logger) Trace(v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) == 0 {
		l.Output(1, TracePrefix, fmt.Sprintln(v...))
	}
}

// Tracef 如果启用调试输出则打印格式化跟踪消息到输出
func (l *Logger) Tracef(format string, v ...interface{}) {
	if atomic.LoadInt32(&l.logLevel) == 0 {
		l.Output(1, TracePrefix, fmt.Sprintf(format, v...))
	}
}
