package main

import (
	"github.com/tech-arch1tect/brx/config"
)

type StarterKitConfig struct {
	config.Config
	Custom AppCustomConfig `envPrefix:"CUSTOM_"`
}

type AppCustomConfig struct {
	ExampleSetting string `env:"EXAMPLE_SETTING" envDefault:"hello world"`
}
