package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
	deflog "log"

	"runtime"
	"runtime/pprof"
	"os/signal"
	"syscall"
	"bufio"

	"github.com/mgutz/ansi"
)

var connection_timeout = 15 * time.Second
var ldapconn_timeout = 15 * time.Second
var connid = uint64(0)
var localAddr = flag.String("l", ":3389", "Local hostname:port")
var remoteAddr = flag.String("r", "localhost:389", "Remote hostname:port")
var enableTLS = flag.Bool("s", false, "Local Enable TLS")
var remoteEnableTLS = flag.Bool("rs", false, "Remote Enable TLS")
var serverName = flag.String("n", "ldap.example.com", "ServerName")
var certFile = flag.String("cert", "/etc/ssl/certs/ssl-cert-snakeoil.pem", "Path to public certificate file")
var keyFile = flag.String("key", "/etc/ssl/private/ssl-cert-snakeoil.key", "Path to certificate key file")
var bindDN = flag.String("bindDN", "", "BindDN for the remote LDAP server")
var bindPWD = flag.String("bindPWD", "", "Bind Password for the remote LDAP server")
var bindPWDFile = flag.String("bindPWDFile", "", "Path to a file that contains Bind Password for the remote LDAP server")
var baseDN = flag.String("baseDN", "", "BaseDN for search user (for Active Directory)")
var attributeName = flag.String("attributeName", "userPrincipalName", "Name of key attribute for search user (for Active Directory)")
var verbose = flag.Bool("v", false, "Verbose mode")
var ultraverbose = flag.Bool("vv", false, "Ultra Verbose mode")
var nagles = flag.Bool("d", false, "Disable Nigle's algorithm on TCP connections")
var hex = flag.Bool("h", false, "Output log by hex")
var colors = flag.Bool("c", false, "Use ansi color terminal")
var mpinServerAddr = flag.String("m", "https://public.milagro.io/mpinAuthenticate", "MPIN Server URL")
var caCertFile = flag.String("cacert", "", "Path to CA certificates file")
var forceMPIN = flag.Bool("f", false, "Force MPIN authentication.")
var testmode = flag.Bool("t", false, "Test mode.  MPIN authentication is simulated.")
var produce_profile = flag.Bool("p", false, "Output profile. May not work on OSX.")

var BindCache *TTLKVS

const SESSION_TTL = 15 * time.Minute

const (
	TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c

	TLS_FALLBACK_SCSV uint16 = 0x5600
)

const (
	CurveP256 uint16 = 23
	CurveP384 uint16 = 24
	CurveP521 uint16 = 25
)

func main() {
	flag.Parse()

	if *produce_profile {
		profile := "profile.prof"
		f, err0 := os.Create(profile)
		if err0 != nil {
			log("Cannot create profile: %v\n", err0)
			return
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		os_signal := make(chan os.Signal, 1)
		signal.Notify(os_signal, os.Interrupt)
		go func() {
			for sig := range os_signal {
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
				log("Stopping profiler and exiting on signal %v\n", sig)
				pprof.StopCPUProfile()
				os.Exit(1)
			}
		}()
	}

	os_stacktrace := make(chan os.Signal, 1)
	signal.Notify(os_stacktrace, syscall.SIGQUIT)
	go func() {
		trace := make([]byte, 65536)
		for range os_stacktrace {
			runtime.Stack(trace, true)
			log("SIGQUIT caught: Number of Goroutine: %v\n%s", runtime.NumGoroutine(), trace)
		}
	}()

	if *ultraverbose {
		*verbose = true
	}

	log("Proxying from %v to %v", *localAddr, *remoteAddr)

	// Read bind password
	if bindPWD == nil || *bindPWD == "" {
		if bindPWDFile != nil && *bindPWDFile != "" {
			pwdfile, err := os.Open(*bindPWDFile)
			if err != nil {
				log("Problem in opening password file: %v\n", err)
				return
			}
			defer pwdfile.Close()
			scanner := bufio.NewScanner(pwdfile)
			for scanner.Scan() {
				if err := scanner.Err(); err != nil {
					log("Problem in parsing password file: %v\n", err)
					return
				}else {
					pwd := scanner.Text()
					if pwd != "" {
						bindPWD = &pwd
						break
					}
				}
			}
		}
	}

	// listen for local connection
	var listener net.Listener
	var err error
	if !*enableTLS {
		listener, err = net.Listen("tcp", *localAddr)
		check(err)
	} else {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		check(err)
		tlsConfig := tls.Config{
			CipherSuites: []uint16{
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA, //not recommended
				TLS_RSA_WITH_AES_128_CBC_SHA, //not recommended
			},
			Certificates:             []tls.Certificate{cert},
			PreferServerCipherSuites: true,
		}
		tlsConfig.ServerName = *serverName
		listener, err = tls.Listen("tcp", *localAddr, &tlsConfig)
		check(err)
	}

	var tlsConfig tls.Config
	if *caCertFile == "" {
		tlsConfig = tls.Config{}
	} else {
		caCert, err := ioutil.ReadFile(*caCertFile)
		check(err)

		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log("Problem in parsing CA certificate file")
			return
		}

		tlsConfig = tls.Config{RootCAs: caCertPool}
	}

	BindCache = NewTTLKVS(SESSION_TTL)


	// on accept, start server
	for {
		if *verbose {
			log("main: Number of Goroutine: %v\n", runtime.NumGoroutine())
		}

		conn, err := listener.Accept()
		if err != nil {
			log("Failed to accept connection '%s'\n", err)
			continue
		}
		connid++
		conn.SetReadDeadline(time.Now().Add(connection_timeout))

		p := &proxy{
			lconn:           conn,
			ldapconnection:  nil,
			localAddr:       *localAddr,
			remoteAddr:      *remoteAddr,
			remoteEnableTLS: *remoteEnableTLS,
			caCertFile:      *caCertFile,
			tlsConfig:       tlsConfig,
			termed:          false,
			sigterm:         make(chan bool),
			id:              fmt.Sprintf("Connection #%d ", connid),
			forwardBind:     !(*forceMPIN),
			loglevel:        0,
		}

		if *hex {
			p.loglevel = 3
		}else if *ultraverbose {
			p.loglevel = 2
		}else if *verbose {
			p.loglevel = 1
		}

		// disable nagles's algorithm
		if *nagles && !*enableTLS {
			(p.lconn.(*net.TCPConn)).SetNoDelay(true)
		}

		go p.start()
	}
}


func check(err error) {
	if err != nil {
		warn(err.Error())
		os.Exit(1)
	}
}

func c(str, style string) string {
	if *colors {
		return ansi.Color(str, style)
	}
	return str
}

func log(f string, args ...interface{}) {
	deflog.Printf(c(f, "green")+"\n", args...)
}

func warn(f string, args ...interface{}) {
	deflog.Printf(c(f, "red")+"\n", args...)
}


