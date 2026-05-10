package custom

import (
	"context"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/proxy"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

func buildNodes(ctx context.Context, nodeConfigList []NodeConfig) (map[string]*proxy.Node, error) {
	nodes := make(map[string]*proxy.Node)
	for _, nodeCfg := range nodeConfigList {
		nodeCfg.Protocol = strings.ToUpper(nodeCfg.Protocol)
		if _, err := tunnel.GetTunnel(nodeCfg.Protocol); err != nil {
			return nil, common.NewError("无效的协议名称:" + nodeCfg.Protocol)
		}
		data, err := yaml.Marshal(nodeCfg.Config)
		common.Must(err)
		nodeContext, err := config.WithYAMLConfig(ctx, data)
		if err != nil {
			return nil, common.NewError("解析 " + nodeCfg.Tag + " 协议 " + nodeCfg.Protocol + " 的配置数据失败").Base(err)
		}
		node := &proxy.Node{
			Name:    nodeCfg.Protocol,
			Next:    make(map[string]*proxy.Node),
			Context: nodeContext,
		}
		nodes[nodeCfg.Tag] = node
	}
	return nodes, nil
}

func init() {
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		cfg := config.FromContext(ctx, Name).(*Config)

		ctx, cancel := context.WithCancel(ctx)
		success := false
		defer func() {
			if !success {
				cancel()
			}
		}()
		// 入站
		nodes, err := buildNodes(ctx, cfg.Inbound.Node)
		if err != nil {
			return nil, err
		}

		var root *proxy.Node
		// 构建服务器树
		for _, path := range cfg.Inbound.Path {
			var lastNode *proxy.Node
			for _, tag := range path {
				if _, found := nodes[tag]; !found {
return nil, common.NewError("无效的节点标签: " + tag)
				}
				if lastNode == nil {
					if root == nil {
						lastNode = nodes[tag]
						root = lastNode
						t, err := tunnel.GetTunnel(root.Name)
						if err != nil {
							return nil, common.NewError("查找根隧道失败").Base(err)
						}
						s, err := t.NewServer(root.Context, nil)
						if err != nil {
							return nil, common.NewError("初始化根服务器失败").Base(err)
						}
						root.Server = s
					} else {
						lastNode = root
					}
				} else {
					lastNode = lastNode.LinkNextNode(nodes[tag])
				}
			}
			lastNode.IsEndpoint = true
		}

		servers := proxy.FindAllEndpoints(root)

		if len(cfg.Outbound.Path) != 1 {
			return nil, common.NewError("出站协议栈必须只有1条路径")
		}

		// 出站
		nodes, err = buildNodes(ctx, cfg.Outbound.Node)
		if err != nil {
			return nil, err
		}

		// 构建客户端栈
		var client tunnel.Client
		for _, tag := range cfg.Outbound.Path[0] {
			if _, found := nodes[tag]; !found {
				return nil, common.NewError("无效的节点标签: " + tag)
			}
			t, err := tunnel.GetTunnel(nodes[tag].Name)
			if err != nil {
				return nil, common.NewError("无效的隧道名称").Base(err)
			}
			client, err = t.NewClient(nodes[tag].Context, client)
			if err != nil {
				return nil, common.NewError("创建客户端失败").Base(err)
			}
		}

		success = true
		return proxy.NewProxy(ctx, cancel, servers, client), nil
	})
}
