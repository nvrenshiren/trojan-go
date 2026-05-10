package config

import (
	"context"
	"encoding/json"

	"gopkg.in/yaml.v3"
)

var creators = make(map[string]Creator)

// Creator 为模块创建默认配置结构
type Creator func() interface{}

// RegisterConfigCreator 注册一个配置结构以供解析
func RegisterConfigCreator(name string, creator Creator) {
	name += "_CONFIG"
	creators[name] = creator
}

func parseJSON(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for name, creator := range creators {
		config := creator()
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
		result[name] = config
	}
	return result, nil
}

func parseYAML(data []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for name, creator := range creators {
		config := creator()
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, err
		}
		result[name] = config
	}
	return result, nil
}

func WithJSONConfig(ctx context.Context, data []byte) (context.Context, error) {
	var configs map[string]interface{}
	var err error
	configs, err = parseJSON(data)
	if err != nil {
		return ctx, err
	}
	for name, config := range configs {
		ctx = context.WithValue(ctx, name, config)
	}
	return ctx, nil
}

func WithYAMLConfig(ctx context.Context, data []byte) (context.Context, error) {
	var configs map[string]interface{}
	var err error
	configs, err = parseYAML(data)
	if err != nil {
		return ctx, err
	}
	for name, config := range configs {
		ctx = context.WithValue(ctx, name, config)
	}
	return ctx, nil
}

func WithConfig(ctx context.Context, name string, cfg interface{}) context.Context {
	name += "_CONFIG"
	return context.WithValue(ctx, name, cfg)
}

// FromContext 从上下文提取配置
func FromContext(ctx context.Context, name string) interface{} {
	return ctx.Value(name + "_CONFIG")
}
