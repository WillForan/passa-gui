// SPDX-License-Identifier: AGPL-3.0
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/adrg/xdg"
)

type config struct {
	Repos     []string `toml:"repos"`
	Keystores []string `toml:"keystores"`
}

func loadConfig() (config, error) {
	paths := []string{filepath.Join(workDir(), "passa.toml"), filepath.Join(xdg.ConfigHome, "passa.toml")}
	for _, configPath := range paths {
		data, err := os.ReadFile(configPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return config{}, fmt.Errorf("read config %q: %w", configPath, err)
		}

		var cfg config
		if _, err := toml.Decode(string(data), &cfg); err != nil {
			return config{}, fmt.Errorf("parse config %q: %w", configPath, err)
		}
		return cfg, nil
	}
	return config{}, nil
}

func configuredPaths(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, configuredPath := range paths {
		if configuredPath == "" {
			continue
		}
		if !filepath.IsAbs(configuredPath) {
			configuredPath = filepath.Join(workDir(), configuredPath)
		}
		result = append(result, filepath.Clean(configuredPath))
	}
	return result
}

var workDir = func() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}
