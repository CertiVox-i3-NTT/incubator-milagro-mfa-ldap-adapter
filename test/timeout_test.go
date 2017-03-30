package ldap

import (
	"net"
	"sync"
	"testing"
	"time"
)

var socketTimeout = 16000 * time.Millisecond

/////////////////////////
func TestSocketTimeout(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	var wg sync.WaitGroup
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	i := 0
	for i < 500 {
		//workaround for MacOS
		time.Sleep(10 * time.Millisecond)
		wg.Add(1)
		go func() {
			conn, err := net.Dial("tcp", proxyString)
			if err != nil {
				t.Errorf("connection failed: %s", err.Error())
				wg.Done()
				return
			}
			time.Sleep(socketTimeout)
			conn.Close()
			wg.Done()
		}()
		i++
	}
	wg.Wait()
	conn, err := net.Dial("tcp", proxyString)
	if err != nil {
		t.Errorf("connection failed after wait: %s", err.Error())
	}
	conn.Close()

	quit <- true
	time.Sleep(3 * time.Second)
}
