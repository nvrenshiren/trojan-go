package proxy

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/constant"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/option"
)

type Option struct {
	path *string
}

func (o *Option) Name() string {
	return Name
}

func detectAndReadConfig(file string) ([]byte, bool, error) {
	isJSON := false
	switch {
	case strings.HasSuffix(file, ".json"):
		isJSON = true
	case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
		isJSON = false
	default:
		log.Fatalf("不支持的配置文件格式: %s。请使用 .yaml 或 .json。", file)
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, false, err
	}
	return data, isJSON, nil
}

func (o *Option) Handle() error {
	defaultConfigPath := []string{
		"config.json",
		"config.yml",
		"config.yaml",
	}

	isJSON := false
	var data []byte
	var err error

	switch *o.path {
	case "":
		log.Warn("未指定配置文件，使用默认路径检测配置文件")
		for _, file := range defaultConfigPath {
			log.Warn("尝试从默认路径加载配置:", file)
			data, isJSON, err = detectAndReadConfig(file)
			if err != nil {
				log.Warn(err)
				continue
			}
			break
		}
	default:
		data, isJSON, err = detectAndReadConfig(*o.path)
		if err != nil {
			log.Fatal(err)
		}
	}

	if data != nil {
		log.Info("trojan-go", constant.Version, "正在初始化")
		proxy, err := NewProxyFromConfigData(data, isJSON)
		if err != nil {
			log.Fatal(err)
		}
		err = proxy.Run()
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal("没有有效的配置")
	return nil
}

func (o *Option) Priority() int {
	return -1
}

func init() {
	option.RegisterHandler(&Option{
		path: flag.String("config", "", "Trojan-Go config filename (.yaml/.yml/.json)"),
	})
	option.RegisterHandler(&StdinOption{
		format:       flag.String("stdin-format", "disabled", "Read from standard input (yaml/json)"),
		suppressHint: flag.Bool("stdin-suppress-hint", false, "Suppress hint text"),
	})
}

type StdinOption struct {
	format       *string
	suppressHint *bool
}

func (o *StdinOption) Name() string {
	return Name + "_STDIN"
}

func (o *StdinOption) Handle() error {
	isJSON, e := o.isFormatJson()
	if e != nil {
		return e
	}

	if o.suppressHint == nil || !*o.suppressHint {
		fmt.Printf("Trojan-Go %s (%s/%s)\n", constant.Version, runtime.GOOS, runtime.GOARCH)
		if isJSON {
			fmt.Println("正在从标准输入读取JSON配置。")
		} else {
			fmt.Println("正在从标准输入读取YAML配置。")
		}
	}

	data, e := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if e != nil {
		log.Fatalf("从标准输入读取失败: %s", e.Error())
	}

	proxy, err := NewProxyFromConfigData(data, isJSON)
	if err != nil {
		log.Fatal(err)
	}
	err = proxy.Run()
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func (o *StdinOption) Priority() int {
	return 0
}

func (o *StdinOption) isFormatJson() (isJson bool, e error) {
	if o.format == nil {
		return false, common.NewError("格式说明符为空")
	}
	if *o.format == "disabled" {
		return false, common.NewError("从标准输入读取已被禁用")
	}
	return strings.ToLower(*o.format) == "json", nil
}
