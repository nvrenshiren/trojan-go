package fingerprint

import (
	"crypto/tls"

	"github.com/p4gefau1t/trojan-go/log"
)

func ParseCipher(s []string) []uint16 {
	all := tls.CipherSuites()
	var result []uint16
	for _, p := range s {
		found := true
		for _, q := range all {
			if q.Name == p {
				result = append(result, q.ID)
				break
			}
			if !found {
				log.Warn("无效的密码套件", p, "已跳过")
			}
		}
	}
	return result
}
