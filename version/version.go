package version

import (
	"flag"
	"fmt"
	"runtime"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/constant"
	"github.com/p4gefau1t/trojan-go/option"
)

type versionOption struct {
	flag *bool
}

func (*versionOption) Name() string {
	return "version"
}

func (*versionOption) Priority() int {
	return 10
}

func (c *versionOption) Handle() error {
	if *c.flag {
		fmt.Println("Trojan-Go", constant.Version)
		fmt.Println("Go版本:", runtime.Version())
		fmt.Println("系统/架构:", runtime.GOOS+"/"+runtime.GOARCH)
		fmt.Println("Git提交:", constant.Commit)
		fmt.Println("")
		fmt.Println("开发者: PageFault (p4gefau1t)")
		fmt.Println("许可证: GNU General Public License version 3")
		fmt.Println("GitHub仓库:\thttps://github.com/nvrenshiren/trojan-go")
		fmt.Println("Trojan-Go文档:\thttps://github.com/nvrenshiren/trojan-go/")
		return nil
	}
	return common.NewError("未设置")
}

func init() {
	option.RegisterHandler(&versionOption{
		flag: flag.Bool("version", false, "显示版本和帮助信息"),
	})
}
