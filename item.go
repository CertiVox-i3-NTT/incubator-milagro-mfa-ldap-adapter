package main

import (
	"sync"
	"time"
)

type Item struct {
	sync.RWMutex
	data    string
	expires *time.Time
}

func (item *Item) touch(ttl time.Duration) {
	item.Lock()
	defer item.Unlock()
	expiration := time.Now().Add(ttl)
	item.expires = &expiration
}



func (item *Item) expired() bool {
	item.RLock()
	defer item.RUnlock()
	if item.expires == nil {
		return true
	} else {
		return item.expires.Before(time.Now())
	}
}
