package freedom

import (
	"encoding/json"
	"time"

	"github.com/p4gefau1t/trojan-go/config"
)

type Config struct {
	LocalHost    string             `json:"local_addr" yaml:"local-addr"`
	LocalPort    int                `json:"local_port" yaml:"local-port"`
	TCP          TCPConfig          `json:"tcp" yaml:"tcp"`
	ForwardProxy ForwardProxyConfig `json:"forward_proxy" yaml:"forward-proxy"`
}

type TCPConfig struct {
	PreferIPV4 bool          `json:"prefer_ipv4" yaml:"prefer-ipv4"`
	KeepAlive  bool          `json:"keep_alive" yaml:"keep-alive"`
	NoDelay    bool          `json:"no_delay" yaml:"no-delay"`
	Timeout    time.Duration `json:"timeout" yaml:"timeout"`
}

func (c *TCPConfig) UnmarshalJSON(data []byte) error {
	type TCPConfigRaw struct {
		PreferIPV4 bool   `json:"prefer_ipv4"`
		KeepAlive  bool   `json:"keep_alive"`
		NoDelay    bool   `json:"no_delay"`
		Timeout    interface{} `json:"timeout"`
	}
	var raw TCPConfigRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.PreferIPV4 = raw.PreferIPV4
	c.KeepAlive = raw.KeepAlive
	c.NoDelay = raw.NoDelay
	c.Timeout = 5 * time.Second

	if raw.Timeout == nil {
		return nil
	}

	switch v := raw.Timeout.(type) {
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			d = 5 * time.Second
		}
		c.Timeout = d
	case float64:
		c.Timeout = time.Duration(v)
	case int:
		c.Timeout = time.Duration(v)
	}
	return nil
}

type ForwardProxyConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	ProxyHost string `json:"proxy_addr" yaml:"proxy-addr"`
	ProxyPort int    `json:"proxy_port" yaml:"proxy-port"`
	Username  string `json:"username" yaml:"username"`
	Password  string `json:"password" yaml:"password"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			TCP: TCPConfig{
				PreferIPV4: false,
				NoDelay:    true,
				KeepAlive:  true,
				Timeout:    5 * time.Second,
			},
		}
	})
}