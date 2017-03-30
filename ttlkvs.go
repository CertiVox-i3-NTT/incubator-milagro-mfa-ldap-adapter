package main

import (
	"sync"
	"time"
)

type TTLKVS struct {
	sync.RWMutex
	ttl      time.Duration
	kvs      map[string]*Item
	shutdown chan bool
}


func (ttlkvs *TTLKVS) Set(key string, data string) {
	ttlkvs.Lock()
	defer ttlkvs.Unlock()
	item := &Item{data: data}
	item.touch(ttlkvs.ttl)
	ttlkvs.kvs[key] = item
}

func (ttlkvs *TTLKVS) Get(key string) (data string, found bool) {
	ttlkvs.RLock()
	defer ttlkvs.RUnlock()
	item, exists := ttlkvs.kvs[key]
	if !exists || item.expired() {
		return "", false
	} else {
		item.touch(ttlkvs.ttl)
		return item.data, true
	}
}

func (ttlkvs *TTLKVS) Count() int {
	ttlkvs.RLock()
	defer ttlkvs.RUnlock()
	return len(ttlkvs.kvs)
}


func (ttlkvs *TTLKVS) cleaner(shutdown chan bool) {
	sigTick := time.Tick(ttlkvs.ttl)
	go (func() {
		for {
			select {
			case <-sigTick:
				func() {
					var expiredKeys []string
					//TODO: Do we need RLock here?
					ttlkvs.RLock()
					for key, item := range ttlkvs.kvs {
						if item.expired() {
							expiredKeys = append(expiredKeys, key)
						}
					}
					ttlkvs.RUnlock()
					if len(expiredKeys) > 0 {
						ttlkvs.Lock()
						for _, voidkey := range expiredKeys {
							voiditem, exists := ttlkvs.kvs[voidkey]
							if exists && voiditem.expired() {
								delete(ttlkvs.kvs, voidkey)
							}
						}
						ttlkvs.Unlock()
					}
				}()
			case <-shutdown:
				return
			}
		}
	})()
}

func (ttlkvs *TTLKVS) Close(){
	ttlkvs.shutdown <- true
}

func NewTTLKVS(ttl time.Duration) *TTLKVS {
	ttlkvs := &TTLKVS{
		ttl:   ttl,
		kvs: map[string]*Item{},
		shutdown: make(chan bool, 1),
	}
	ttlkvs.cleaner(ttlkvs.shutdown)
	return ttlkvs
}

