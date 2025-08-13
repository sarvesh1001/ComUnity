package config

import (
    "os"
    "reflect"
    "strconv"
    "strings"

    "gopkg.in/yaml.v2"
)

// LoadConfig loads configuration from YAML and environment variables
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Expand environment variables in YAML
	expanded := os.ExpandEnv(string(data))
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func overrideWithEnv(cfg *Config) error {
    v := reflect.ValueOf(cfg).Elem()
    t := v.Type()

    for i := 0; i < t.NumField(); i++ {
        field := t.Field(i)
        envKey := field.Tag.Get("env")
        if envKey == "" {
            continue
        }

        envValue, exists := os.LookupEnv(envKey)
        if !exists {
            continue
        }

        fieldVal := v.Field(i)
        switch fieldVal.Kind() {
        case reflect.String:
            fieldVal.SetString(envValue)
        case reflect.Int:
            if intValue, err := strconv.Atoi(envValue); err == nil {
                fieldVal.SetInt(int64(intValue))
            }
        case reflect.Bool:
            if boolValue, err := strconv.ParseBool(envValue); err == nil {
                fieldVal.SetBool(boolValue)
            }
        case reflect.Slice:
            if field.Type.Elem().Kind() == reflect.String {
                sliceValue := strings.Split(envValue, ",")
                fieldVal.Set(reflect.ValueOf(sliceValue))
            }
        }
    }
    return nil
}