package url

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleTrojanPort_Default(t *testing.T) {
	port, e := handleTrojanPort("")
	assert.Nil(t, e, "空端口不应报错")
	assert.EqualValues(t, 443, port, "空端口应回退到443")
}

func TestHandleTrojanPort_NotNumber(t *testing.T) {
	_, e := handleTrojanPort("fuck")
	assert.Error(t, e, "非数字端口应报错")
}

func TestHandleTrojanPort_GoodNumber(t *testing.T) {
	testCases := []string{"443", "8080", "10086", "80", "65535", "1"}
	for _, testCase := range testCases {
		_, e := handleTrojanPort(testCase)
		assert.Nil(t, e, "有效的端口 %s 不应报错", testCase)
	}
}

func TestHandleTrojanPort_InvalidNumber(t *testing.T) {
	testCases := []string{"443.0", "443.000", "8e2", "3.5", "9.99", "-1", "-65535", "65536", "0"}

	for _, testCase := range testCases {
		_, e := handleTrojanPort(testCase)
		assert.Error(t, e, "无效数字端口 %s 应报错", testCase)
	}
}

func TestNewShareInfoFromURL_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("")
	assert.Error(t, e, "空链接应导致错误")
}

func TestNewShareInfoFromURL_RandomCrap(t *testing.T) {
	for i := 0; i < 100; i++ {
		randomCrap, _ := ioutil.ReadAll(io.LimitReader(crand.Reader, 10))
		_, e := NewShareInfoFromURL(string(randomCrap))
		assert.Error(t, e, "随机数据 %v 应导致错误", randomCrap)
	}
}

func TestNewShareInfoFromURL_NotTrojanGo(t *testing.T) {
	testCases := []string{
		"trojan://what.ever@www.twitter.com:443?allowInsecure=1&allowInsecureHostname=1&allowInsecureCertificate=1&sessionTicket=0&tfo=1#some-trojan",
		"ssr://d3d3LnR3aXR0ZXIuY29tOjgwOmF1dGhfc2hhMV92NDpjaGFjaGEyMDpwbGFpbjpZbkpsWVd0M1lXeHMvP29iZnNwYXJhbT0mcmVtYXJrcz02TC1INXB5ZjVwZTI2WmUwNzd5YU1qQXlNQzB3TnkweE9DQXhNam8xTlRveU1RJmdyb3VwPVEzUkRiRzkxWkNCVFUxSQ",
		"vmess://eyJhZGQiOiJtb3RoZXIuZnVja2VyIiwiYWlkIjowLCJpZCI6IjFmYzI0NzVmLThmNDMtM2FlYi05MzUyLTU2MTFhZjg1NmQyOSIsIm5ldCI6InRjcCIsInBvcnQiOjEwMDg2LCJwcyI6Iui/h+acn+aXtumXtO+8mjIwMjAtMDYtMjMiLCJ0bHMiOiJub25lIiwidHlwZSI6Im5vbmUiLCJ2IjoyfQ==",
	}

	for _, testCase := range testCases {
		_, e := NewShareInfoFromURL(testCase)
		assert.Error(t, e, "非trojan-go链接 %s 无法解析", testCase)
	}
}

func TestNewShareInfoFromURL_EmptyTrojanHost(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://fuckyou@:443/")
	assert.Error(t, e, "空主机无法解析")
}

func TestNewShareInfoFromURL_BadPassword(t *testing.T) {
	testCases := []string{
		"trojan-go://we:are:the:champion@114514.go",
		"trojan-go://evilpassword:@1919810.me",
		"trojan-go://evilpassword::@1919810.me",
		"trojan-go://@password.404",
		"trojan-go://mother.fuck#yeah",
	}

	for _, testCase := range testCases {
		_, e := NewShareInfoFromURL(testCase)
		assert.Error(t, e, "密码错误的链接 %s 无法解析", testCase)
	}
}

func TestNewShareInfoFromURL_GoodPassword(t *testing.T) {
	testCases := []string{
		"trojan-go://we%3Aare%3Athe%3Achampion@114514.go",
		"trojan-go://evilpassword%3A@1919810.me",
		"trojan-go://passw0rd-is-a-must@password.200",
	}

	for _, testCase := range testCases {
		_, e := NewShareInfoFromURL(testCase)
		assert.Nil(t, e, "密码正确的链接 %s 可以解析", testCase)
	}
}

func TestNewShareInfoFromURL_BadPort(t *testing.T) {
	testCases := []string{
		"trojan-go://pswd@example.com:114514",
		"trojan-go://pswd@example.com:443.0",
		"trojan-go://pswd@example.com:-1",
		"trojan-go://pswd@example.com:8e2",
		"trojan-go://pswd@example.com:65536",
	}

	for _, testCase := range testCases {
		_, e := NewShareInfoFromURL(testCase)
		assert.Error(t, e, "解析端口无效的URL %s 应报错", testCase)
	}
}

func TestNewShareInfoFromURL_BadQuery(t *testing.T) {
	testCases := []string{
		"trojan-go://cao@ni.ma?NMSL=%CG%GE%CAONIMA",
		"trojan-go://ni@ta.ma:13/?#%2e%fu",
	}

	for _, testCase := range testCases {
		_, e := NewShareInfoFromURL(testCase)
		assert.Error(t, e, "解析错误查询参数应报错")
	}
}

func TestNewShareInfoFromURL_SNI_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?sni=")
	assert.Error(t, e, "空SNI不应被允许")
}

func TestNewShareInfoFromURL_SNI_Default(t *testing.T) {
	info, e := NewShareInfoFromURL("trojan-go://a@b.c")
	assert.Nil(t, e)
	assert.Equal(t, info.TrojanHost, info.SNI, "默认SNI应为trojan主机名")
}

func TestNewShareInfoFromURL_SNI_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?sni=a&sni=b&sni=c")
	assert.Error(t, e, "不应允许多个SNI")
}

func TestNewShareInfoFromURL_Type_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=")
	assert.Error(t, e, "空类型不应被允许")
}

func TestNewShareInfoFromURL_Type_Default(t *testing.T) {
	info, e := NewShareInfoFromURL("trojan-go://a@b.c")
	assert.Nil(t, e)
	assert.Equal(t, ShareInfoTypeOriginal, info.Type, "默认类型应为original")
}

func TestNewShareInfoFromURL_Type_Invalid(t *testing.T) {
	invalidTypes := []string{"nmsl", "dio"}
	for _, invalidType := range invalidTypes {
		_, e := NewShareInfoFromURL(fmt.Sprintf("trojan-go://a@b.c?type=%s", invalidType))
		assert.Error(t, e, "%s 不是有效的类型", invalidType)
	}
}

func TestNewShareInfoFromURL_Type_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=a&type=b&type=c")
	assert.Error(t, e, "不应允许多个类型")
}

func TestNewShareInfoFromURL_Host_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?host=")
	assert.Error(t, e, "空主机不应被允许")
}

func TestNewShareInfoFromURL_Host_Default(t *testing.T) {
	info, e := NewShareInfoFromURL("trojan-go://a@b.c")
	assert.Nil(t, e)
	assert.Equal(t, info.TrojanHost, info.Host, "默认主机应为trojan主机名")
}

func TestNewShareInfoFromURL_Host_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?host=a&host=b&host=c")
	assert.Error(t, e, "不应允许多个主机")
}

func TestNewShareInfoFromURL_Type_WS_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=ws&path=a&path=b&path=c")
	assert.Error(t, e, "在wss中不应允许多个路径")
}

func TestNewShareInfoFromURL_Path_WS_None(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=ws")
	assert.Error(t, e, "ws需要路径")
}

func TestNewShareInfoFromURL_Path_WS_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=ws&path=")
	assert.Error(t, e, "ws中空路径不应被允许")
}

func TestNewShareInfoFromURL_Path_WS_Invalid(t *testing.T) {
	invalidPaths := []string{"../", ".+!", " "}
	for _, invalidPath := range invalidPaths {
		_, e := NewShareInfoFromURL(fmt.Sprintf("trojan-go://a@b.c?type=ws&path=%s", invalidPath))
		assert.Error(t, e, "%s 在ws中不是有效的路径", invalidPath)
	}
}

func TestNewShareInfoFromURL_Path_Plain_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?type=original&path=")
	assert.Nil(t, e, "在original模式下空路径应被忽略")
}

func TestNewShareInfoFromURL_Encryption_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?encryption=")
	assert.Error(t, e, "加密不应为空")
}

func TestNewShareInfoFromURL_Encryption_Unknown(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?encryption=motherfucker")
	assert.Error(t, e, "不支持的加密方式")
}

func TestNewShareInfoFromURL_Encryption_None(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://what@ever.me?encryption=none")
	assert.Nil(t, e, "应支持none加密")
}

func TestNewShareInfoFromURL_Encryption_SS_NotSupportedMethods(t *testing.T) {
	invalidMethods := []string{"rc4-md5", "rc4", "des-cfb", "table", "salsa20-ctr"}
	for _, invalidMethod := range invalidMethods {
		_, e := NewShareInfoFromURL(fmt.Sprintf("trojan-go://a@b.c?encryption=ss%%3B%s%%3Ashabi", invalidMethod))
		assert.Error(t, e, "SS不支持加密方式 %s", invalidMethod)
	}
}

func TestNewShareInfoFromURL_Encryption_SS_NoPassword(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?encryption=ss%3Baes-256-gcm%3A")
	assert.Error(t, e, "空SS密码不应被允许")
}

func TestNewShareInfoFromURL_Encryption_SS_BadParams(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?encryption=ss%3Ba")
	assert.Error(t, e, "损坏的SS参数不应被允许")
}

func TestNewShareInfoFromURL_Encryption_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?encryption=a&encryption=b&encryption=c")
	assert.Error(t, e, "不应允许多个加密")
}

func TestNewShareInfoFromURL_Plugin_Empty(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?plugin=")
	assert.Error(t, e, "插件不应为空")
}

func TestNewShareInfoFromURL_Plugin_Multiple(t *testing.T) {
	_, e := NewShareInfoFromURL("trojan-go://a@b.c?plugin=a&plugin=b&plugin=c")
	assert.Error(t, e, "不应允许多个插件")
}
