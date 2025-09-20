package cache

import (
	"fmt"
	"github.com/iilun/f5-mock/pkg/models"
	"gopkg.in/yaml.v3"
	"os"
)

type SeedData struct {
	ClientSSLProfiles []*models.ClientSSLProfile `yaml:"client_ssl_profiles"`
}

func loadSeedData(path string) (SeedData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SeedData{}, fmt.Errorf("failed to read file: %w", err)
	}

	var seed SeedData
	if err := yaml.Unmarshal(data, &seed); err != nil {
		return SeedData{}, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	return seed, nil
}
