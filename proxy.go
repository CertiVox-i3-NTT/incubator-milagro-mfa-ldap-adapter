package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	//"gopkg.in/asn1-ber.v1"
	"github.com/CertiVox-i3-NTT/asn1-ber"
	//"gopkg.in/ldap.v2"
	"github.com/CertiVox-i3-NTT/ldap"
	"errors"
	"sync"
	"time"
)


//proxy class
type proxy struct {
	sentBytes             uint64
	receivedBytes         uint64
	localAddr, remoteAddr string
	remoteEnableTLS       bool
	caCertFile            string
	tlsConfig             tls.Config
	lconn, rconn          net.Conn
	termed                bool
	sigterm               chan bool
	id                    string
	bindCache             *TTLKVS  // TODO: bindcache should be shared by all proxy instances
	ldapconnection        *ldap.Conn
	forwardBind           bool
	loglevel int
}

func (p *proxy) debugLog(s string, args ...interface{}) {
	if p.loglevel>=1 {
		level := "D "
		log(level+p.id+s, args...)
	}
}

func (p *proxy) infoLog(s string, args ...interface{}) {
	if p.loglevel>=1 {
		level := "I "
		log(level+p.id+s, args...)
	}
}

func (p *proxy) errLog(s string, args ...interface{}) {
	if p.loglevel>=1 {
		level := "E "
		log(level+p.id+s, args...)
	}
}
func (p *proxy) warnLog(s string, args ...interface{}) {
	if p.loglevel>=1 {
		level := "W "
		log(level+p.id+s, args...)
	}
}

func (p *proxy) err(s string, err error) {
	if p.termed {
		return
	}
	level := "E "
	if err != io.EOF {
		warn(level+p.id+s, err)
	} else if p.loglevel >= 2 {
		log(level+p.id+s, err)
	}

	p.sigterm <- true
}

func (p *proxy) ldapConnect() {
	var err error
	finished := make(chan bool)
	if p.ldapconnection == nil {
		go func() {
			if !p.remoteEnableTLS {
				p.ldapconnection, err = ldap.Dial("tcp", p.remoteAddr)
				if err != nil {
					p.err(" Remote LDAP connection failed: %s", err)
					return
				}
			} else {
				tlsConfig := p.tlsConfig
				reg, _ := regexp.Compile(":[0-9]+$")
				tlsConfig.ServerName = reg.ReplaceAllString(p.remoteAddr, "")
				p.ldapconnection, err = ldap.DialTLS("tcp", p.remoteAddr, &tlsConfig)
				if err != nil {
					p.err(" Remote LDAP connection failed: %s", err)
					return
				}
			}
			// try bind
			if *bindDN != "" && *bindPWD != "" {
				err = p.ldapconnection.Bind(*bindDN, *bindPWD)
				if err != nil {
					p.errLog(" Bind failed: %v\n", err)
				} else {
					p.infoLog(" Bind not failed")
				}
			}
			finished <- true
		}()
		select {
		case <-finished:
		case <-time.After(ldapconn_timeout):
			p.ldapClose()
		}
		return
	}
}

func (p *proxy) ldapSearch(SearchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if p.ldapconnection != nil {
		var result *ldap.SearchResult
		var err error
		finished := make(chan bool)
		go func() {
			result, err = p.ldapconnection.Search(SearchRequest)
			finished <- true
		}()
		select {
		case <-finished:
			return result, err
		case <-time.After(ldapconn_timeout):
			return &ldap.SearchResult{}, ldap.NewError(ldap.LDAPResultOperationsError, errors.New("LDAP search timed out"))
		}
	} else {
		return &ldap.SearchResult{}, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("LDAP connection for search failed"))
	}
}

func (p *proxy) ldapClose() {
	if p.ldapconnection != nil {
		p.ldapconnection.Close()
		p.ldapconnection = nil
	}
}

//server main
func (p *proxy) start() {
	var err error
	defer p.lconn.Close()
	//open connection to remote
	if !p.remoteEnableTLS {
		p.rconn, err = net.Dial("tcp", p.remoteAddr)
		if err != nil {
			p.err(" Remote connection failed: %s", err)
			return
		}
	} else {
		p.rconn, err = tls.Dial("tcp", p.remoteAddr, &p.tlsConfig)
		if err != nil {
			p.err(" Remote connection failed: %s", err)
			return
		}
	}
	defer p.rconn.Close()
	p.rconn.SetReadDeadline(time.Now().Add(connection_timeout))

	//p.ldapConnect()
	//defer p.ldapClose()

	//disable nagle's algorithm
	if *nagles {
		(p.rconn.(*net.TCPConn)).SetNoDelay(true)
	}

	// proxy established
	p.infoLog(" Opened %s >>> %s", p.lconn.RemoteAddr().String(), p.rconn.RemoteAddr().String())

	// prepare Bind cache
	//p.bindCache = ttlkvs.NewTTLKVS(SESSION_TTL)
	p.bindCache = BindCache

	//
	//bidirectional copy.  get aux packet from Remote and send it to Local
	//

	// channel that carries Packets from analyzer to the output of the other pipe.
	interruptRtoL := make(chan *ber.Packet)

	// set signals for termination.  Once sigterm is invoked then the two pipes should terminate gracefully
	sigLR := make(chan time.Time)
	sigRL := make(chan time.Time)
	go func() {
		<-p.sigterm
		p.termed = true
		go func() {
			sigLR <- time.Now()
			close(sigLR)
		}()
		go func() {
			sigRL <- time.Now()
			close(sigRL)
		}()
		//continue receiving sigterm until it is closed
		for range p.sigterm {}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	// L to R pipe, with analyzer and get aux packet
	go p.pipe(p.lconn, p.rconn, p.analyzerIncomingLDAP, nil, interruptRtoL, sigLR, wg.Done)
	// R to L pipe, put aux packet
	go p.pipe(p.rconn, p.lconn, nil, interruptRtoL, nil, sigRL, wg.Done)

	//wait for close
	wg.Wait()
	p.lconn.Close()
	p.rconn.Close()
	p.ldapClose()
	close(p.sigterm)
	//p.bindCache.Close()
	p.infoLog(" Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

// pipe from src to dst by ber packet.  packets are analyzed by analyzer
// packets from inbound channel are inserted to the pipe.
// analyzer outputs packets and they are sent to outbound channel.
func (p *proxy) pipe(src, dst net.Conn, analyzer func(*ber.Packet, chan *ber.Packet) *ber.Packet, inbound chan *ber.Packet, outbound chan *ber.Packet, sig chan time.Time, done func()) {
	//data direction
	islocal := src == p.lconn

	// Read buffer channel
	inread := make(chan *ber.Packet, 2048)
	//TODO: make channel inread resizable if we really need guarantee not to drop any packet.

	readDone := make(chan bool)
	//new thread that reads from src and transmit to inread
	//finish if EOF
	go func(in chan *ber.Packet) {
		for {

			if p.termed {
				readDone <- true
				return
			}

			src.SetReadDeadline(time.Now().Add(connection_timeout))
			packet, err := ber.ReadPacket(src)

			//if err != nil && strings.Index(string(err.Error()), ": i/o timeout") != -1 {
			//	continue
			//}
			if err != nil {
				p.err(" Read failed '%s'", err)
				readDone <- true
				return
			} else {
					in <- packet
			}
		}
	}(inread)

	for {
		var packet *ber.Packet
		var ok bool
		var terminator <-chan time.Time

		if p.termed {
			// termination mode.
			// If chanel buffers are empty then terminate.
			if len(inbound) == 0 && len(inread) == 0 {
				<-sig
				<-readDone
				done()
				if inbound != nil {
					close(inbound)
				}
				return
			}
			terminator = time.After(connection_timeout)
		} else {
			terminator = sig
		}

		if len(inread) == cap(inread) {
			p.warnLog(" Warning: Read channel buffer full.")
		}

		// Wait for input either from inbound or inread with timeout triggered by terminator
		select {
		case packet, ok = <-inbound:
			if ok {
				if p.loglevel >= 1 {
					p.logPacket(packet.Bytes(), islocal)
				}
			} else {
				p.err(" inbound %v\n", errors.New("channel closed"))
				<-sig
			}
		case packet, ok = <-inread:
			if ok {
				if p.loglevel >= 1 {
					p.logPacket(packet.Bytes(), islocal)
				}
				// analyze
				if analyzer != nil {
					analyzedBuffer := analyzer(packet, outbound)
					if analyzedBuffer != nil {
						packet= analyzedBuffer
						p.infoLog(" Not MPIN Authentication. Proxy to LDAPServer.")
					} else {
						packet = nil
					}
				}
			} else {
				p.err(" inread %v\n", errors.New("channel closed"))
				<-sig
			}
		case <-terminator:
		}

		//write packet to remote
		if packet != nil {
			n, err := dst.Write(packet.Bytes())
			if err != nil {
				p.err(" Write failed '%s'\n", err)
				<-sig
				<-readDone
				done()
				if inbound != nil {
					close(inbound)
				}
				return
			}
			if islocal {
				p.sentBytes += uint64(n)
			} else {
				p.receivedBytes += uint64(n)
			}
		}
	}
}


//helper functions

func (p *proxy) logPacket(b []byte, islocal bool) {
	var f string

	if islocal {
		f = ">>> %d bytes sent%s"
	} else {
		f = "<<< %d bytes recieved%s"
	}
	n := len(b)
	//show output
	if p.loglevel >=2 {
		if p.loglevel >=3 {
			p.debugLog(f, n, "\n"+c(fmt.Sprintf("%x", b), "yellow"))
		}
		p.debugLog(f, n, "")
		decoded_b, err := ber.ReadPacket(bytes.NewBuffer(b))
		if err == nil && decoded_b != nil {
			ber.PrintPacket(decoded_b)
		}
	} else {
		p.debugLog(f, n, "")
	}

}

