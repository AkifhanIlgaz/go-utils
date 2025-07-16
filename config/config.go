package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type TokenConfig struct {
	PrivateKeyPath        string `mapstructure:"private_key_path"`
	PublicKeyPath         string `mapstructure:"public_key_path"`
	AccessTokenExpiresIn  int    `mapstructure:"access_token_expires_in"`  // minutes
	RefreshTokenExpiresIn int    `mapstructure:"refresh_token_expires_in"` // days
}

type RedisConfig struct {
	ConnString string `mapstructure:"connection_string"`
}

type MongoConfig struct {
	ConnString string `mapstructure:"connection_string"`
}

type AppConfig struct {
	Token TokenConfig `mapstructure:"token"`
	Port  int         `mapstructure:"port"`
	Redis RedisConfig `mapstructure:"redis"`
	Mongo MongoConfig `mapstructure:"mongo"`
}

func Load() (AppConfig, error) {
	var config AppConfig

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config/")

	err := viper.ReadInConfig()
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}
