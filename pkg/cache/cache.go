package cache

import (
	"F5Mock/pkg/models"
	"context"
	"github.com/allegro/bigcache/v3"
	"sync"
	"time"
)

type MemoryCaches struct {
	AuthTokens        *bigcache.BigCache
	ClientSSLProfiles []models.ClientSSLProfile
}

var once sync.Once

var GlobalCache *MemoryCaches

func New() (*MemoryCaches, error) {
	var err error
	once.Do(func() {
		var authCache *bigcache.BigCache
		authCache, err = bigcache.New(context.Background(), bigcache.Config{
			LifeWindow:  20 * time.Minute,
			CleanWindow: 30 * time.Second,
		})

		GlobalCache = &MemoryCaches{AuthTokens: authCache}
	})
	return GlobalCache, err
}
