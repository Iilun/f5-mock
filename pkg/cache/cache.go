package cache

import (
	"context"
	"github.com/allegro/bigcache/v3"
	"github.com/iilun/f5-mock/pkg/models"
	"sync"
	"time"
)

type MemoryCaches struct {
	AuthTokens        *bigcache.BigCache
	ClientSSLProfiles []*models.ClientSSLProfile
	Fs                *MemoryFS
}

var once sync.Once

var GlobalCache *MemoryCaches

func New(seedDatapath string) (*MemoryCaches, error) {
	var err error

	once.Do(func() {
		var authCache *bigcache.BigCache

		authCache, err = bigcache.New(context.Background(), bigcache.DefaultConfig(20*time.Minute))
		if err != nil {
			return
		}

		var seedData SeedData
		if seedDatapath != "" {
			seedData, err = loadSeedData(seedDatapath)
			if err != nil {
				return
			}
		}

		GlobalCache = &MemoryCaches{
			AuthTokens:        authCache,
			Fs:                NewFS(),
			ClientSSLProfiles: seedData.ClientSSLProfiles,
		}
	})
	return GlobalCache, err
}
