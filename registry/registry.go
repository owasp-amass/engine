package registry

// plugin registry for both statically linked plugins and Go Plugin based ones

import (
	"fmt"
	"os"
	"plugin"
	"strings"
)

type PluginRegistry struct {
	Plugins map[string]AmassPlugin
}

func NewRegistry() *PluginRegistry {
	return &PluginRegistry{
		Plugins: make(map[string]AmassPlugin),
	}
}

func (r *PluginRegistry) LoadPlugins(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".so") {
			p, err := r.loadPlugin(dir + "/" + file.Name())
			if err != nil {
				fmt.Printf("Error loading plugin %s: %s\n", file.Name(), err)
				continue
			}
			r.Plugins[file.Name()] = p
		}
	}
	return nil
}

func (r *PluginRegistry) loadPlugin(path string) (AmassPlugin, error) {
	plug, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	symPlugin, err := plug.Lookup("Plugin")
	if err != nil {
		return nil, err
	}

	var myPlugin AmassPlugin
	myPlugin, ok := symPlugin.(AmassPlugin)
	if !ok {
		return nil, fmt.Errorf("unexpected type from module symbol")
	}

	return myPlugin, nil
}
