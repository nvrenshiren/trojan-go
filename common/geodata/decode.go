// Package geodata 包含用于解码和解析geoip和geosite数据文件的工具。
//
// 它依赖于github.com/v2fly/v2ray-core/v4/app/router/config.proto中GeoIP、GeoIPList、GeoSite和GeoSiteList的proto结构，并遵循以下规则:
//
// 1. GeoIPList和GeoSiteList不能被更改
// 2. GeoIP和GeoSite中的country_code必须是
//    长度分隔的`string`(wire类型)且field_number设置为1
//
package geodata

import (
	"errors"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

var (
	ErrFailedToReadBytes            = errors.New("读取字节失败")
	ErrFailedToReadExpectedLenBytes = errors.New("读取预期长度的字节失败")
	ErrInvalidGeodataFile           = errors.New("无效的geodata文件")
	ErrInvalidGeodataVarintLength   = errors.New("无效的geodata varint长度")
	ErrCodeNotFound                 = errors.New("代码未找到")
)

func EmitBytes(f io.ReadSeeker, code string) ([]byte, error) {
	count := 1
	isInner := false
	tempContainer := make([]byte, 0, 5)

	var result []byte
	var advancedN uint64 = 1
	var geoDataVarintLength, codeVarintLength, varintLenByteLen uint64 = 0, 0, 0

Loop:
	for {
		container := make([]byte, advancedN)
		bytesRead, err := f.Read(container)
		if err == io.EOF {
			return nil, ErrCodeNotFound
		}
		if err != nil {
			return nil, ErrFailedToReadBytes
		}
		if bytesRead != len(container) {
			return nil, ErrFailedToReadExpectedLenBytes
		}

		switch count {
		case 1, 3: // 数据类型 ((field_number << 3) | wire_type)
			if container[0] != 10 { // 字节 `0A` 等于十进制的 `10`
				return nil, ErrInvalidGeodataFile
			}
			advancedN = 1
			count++
		case 2, 4: // 数据长度
			tempContainer = append(tempContainer, container...)
			if container[0] > 127 { // 最大单字节长度字节 `7F`(0FFF FFFF) 等于十进制的 `127`
				advancedN = 1
				goto Loop
			}
			lenVarint, n := protowire.ConsumeVarint(tempContainer)
			if n < 0 {
				return nil, ErrInvalidGeodataVarintLength
			}
			tempContainer = nil
			if !isInner {
				isInner = true
				geoDataVarintLength = lenVarint
				advancedN = 1
			} else {
				isInner = false
				codeVarintLength = lenVarint
				varintLenByteLen = uint64(n)
				advancedN = codeVarintLength
			}
			count++
		case 5: // 数据值
			if strings.EqualFold(string(container), code) {
				count++
				offset := -(1 + int64(varintLenByteLen) + int64(codeVarintLength))
				f.Seek(offset, 1)               // 返回到GeoIP或GeoSite varint的开头
				advancedN = geoDataVarintLength // 下一轮要读取的字节数
			} else {
				count = 1
				offset := int64(geoDataVarintLength) - int64(codeVarintLength) - int64(varintLenByteLen) - 1
				f.Seek(offset, 1) // 跳过不匹配的GeoIP或GeoSite varint
				advancedN = 1     // 下一轮将是另一个GeoIPList或GeoSiteList的开始
			}
		case 6: // 匹配的GeoIP或GeoSite varint
			result = container
			break Loop
		}
	}

	return result, nil
}

func Decode(filename, code string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	geoBytes, err := EmitBytes(f, code)
	if err != nil {
		return nil, err
	}
	return geoBytes, nil
}
