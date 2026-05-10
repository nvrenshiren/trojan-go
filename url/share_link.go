package url

import (
	"errors"
	"fmt"
	neturl "net/url"
	"strconv"
	"strings"
)

const (
	ShareInfoTypeOriginal  = "original"
	ShareInfoTypeWebSocket = "ws"
)

var validTypes = map[string]struct{}{
	ShareInfoTypeOriginal:  {},
	ShareInfoTypeWebSocket: {},
}

var validEncryptionProviders = map[string]struct{}{
	"ss":   {},
	"none": {},
}

var validSSEncryptionMap = map[string]struct{}{
	"aes-128-gcm":            {},
	"aes-256-gcm":            {},
	"chacha20-ietf-poly1305": {},
}

type ShareInfo struct {
	TrojanHost     string // 节点 IP / 域名
	Port           uint16 // 节点端口
	TrojanPassword string // Trojan 密码

	SNI  string // SNI
	Type string // 类型
	Host string // HTTP Host Header

	Path       string // WebSocket / H2 Path
	Encryption string // 额外加密
	Plugin     string // 插件设定

	Description string // 节点说明
}

func NewShareInfoFromURL(shareLink string) (info ShareInfo, e error) {
	// 分享链接必须是有效的URL
	parse, e := neturl.Parse(shareLink)
	if e != nil {
		e = fmt.Errorf("无效的URL: %s", e.Error())
		return
	}

	// 分享链接必须包含 `trojan-go://` 协议
	if parse.Scheme != "trojan-go" {
		e = errors.New("URL缺少trojan-go://协议头")
		return
	}

	// 密码
	if info.TrojanPassword = parse.User.Username(); info.TrojanPassword == "" {
		e = errors.New("未指定密码")
		return
	} else if _, hasPassword := parse.User.Password(); hasPassword {
		e = errors.New("密码中冒号可能缺少百分比编码")
		return
	}

	// trojanHost: 不能为空 & 去除IPv6地址的[]
	if info.TrojanHost = parse.Hostname(); info.TrojanHost == "" {
		e = errors.New("主机名为空")
		return
	}

	// 端口
	if info.Port, e = handleTrojanPort(parse.Port()); e != nil {
		return
	}

	// 严格解析查询参数
	query, e := neturl.ParseQuery(parse.RawQuery)
	if e != nil {
		return
	}

	// SNI
	if SNIs, ok := query["sni"]; !ok {
		info.SNI = info.TrojanHost
	} else if len(SNIs) > 1 {
		e = errors.New("存在多个SNI")
		return
	} else if info.SNI = SNIs[0]; info.SNI == "" {
		e = errors.New("SNI为空")
		return
	}

	// 类型
	if types, ok := query["type"]; !ok {
		info.Type = ShareInfoTypeOriginal
	} else if len(types) > 1 {
		e = errors.New("存在多个传输类型")
		return
	} else if info.Type = types[0]; info.Type == "" {
		e = errors.New("传输类型为空")
		return
	} else if _, ok := validTypes[info.Type]; !ok {
		e = fmt.Errorf("未知的传输类型: %s", info.Type)
		return
	}

	// 主机
	if hosts, ok := query["host"]; !ok {
		info.Host = info.TrojanHost
	} else if len(hosts) > 1 {
		e = errors.New("存在多个主机")
		return
	} else if info.Host = hosts[0]; info.Host == "" {
		e = errors.New("主机为空")
		return
	}

	// 路径
	if info.Type == ShareInfoTypeWebSocket {
		if paths, ok := query["path"]; !ok {
			e = errors.New("WebSocket模式下必须指定路径")
			return
		} else if len(paths) > 1 {
			e = errors.New("存在多个路径")
			return
		} else if info.Path = paths[0]; info.Path == "" {
			e = errors.New("路径为空")
			return
		}

		if !strings.HasPrefix(info.Path, "/") {
			e = errors.New("路径必须以/开头")
			return
		}
	}

	// 加密
	if encryptionArr, ok := query["encryption"]; !ok {
		// 无加密，可以接受
	} else if len(encryptionArr) > 1 {
		e = errors.New("存在多个加密字段")
		return
	} else if info.Encryption = encryptionArr[0]; info.Encryption == "" {
		e = errors.New("加密为空")
		return
	} else {
		encryptionParts := strings.SplitN(info.Encryption, ";", 2)
		encryptionProviderName := encryptionParts[0]

		if _, ok := validEncryptionProviders[encryptionProviderName]; !ok {
			e = fmt.Errorf("不支持的加密提供者: %s", encryptionProviderName)
			return
		}

		var encryptionParams string
		if len(encryptionParts) >= 2 {
			encryptionParams = encryptionParts[1]
		}

		if encryptionProviderName == "ss" {
			ssParams := strings.SplitN(encryptionParams, ":", 2)
			if len(ssParams) < 2 {
				e = errors.New("缺少SS密码")
				return
			}

			ssMethod, ssPassword := ssParams[0], ssParams[1]
			if _, ok := validSSEncryptionMap[ssMethod]; !ok {
				e = fmt.Errorf("不支持的SS加密方式: %s", ssMethod)
				return
			}

			if ssPassword == "" {
				e = errors.New("SS密码不能为空")
				return
			}
		}
	}

	// 插件
	if plugins, ok := query["plugin"]; !ok {
		// 无插件，可以接受
	} else if len(plugins) > 1 {
		e = errors.New("存在多个插件")
		return
	} else if info.Plugin = plugins[0]; info.Plugin == "" {
		e = errors.New("插件为空")
		return
	}

	// 描述
	info.Description = parse.Fragment

	return
}

func handleTrojanPort(p string) (port uint16, e error) {
	if p == "" {
		return 443, nil
	}

	portParsed, e := strconv.Atoi(p)
	if e != nil {
		return
	}

	if portParsed < 1 || portParsed > 65535 {
		e = fmt.Errorf("无效的端口 %d", portParsed)
		return
	}

	port = uint16(portParsed)
	return
}
