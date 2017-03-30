# LDAP-adapter

## What is this?
This code adds MPIN authentication to applications that use LDAP authentication by acting as a LDAP proxy between the applications and the LDAP servers.

## How to build?
Just do
`go build`.


## How to use?

    Usage:
    -attributeName string
    	Name of key attribute for search user (for Active Directory) (default "userPrincipalName")
    -baseDN string
    	BaseDN for search user (for Active Directory)
    -bindDN string
    	BindDN for the remote LDAP server
    -bindPWD string
    	Bind Password for the remote LDAP server
    -bindPWDFile string
    	Path to a file that contains Bind Password for the remote LDAP server
    -c	Use ansi color terminal
    -cacert string
    	Path to CA certificates file
    -cert string
    	Path to public certificate file (default "/etc/ssl/certs/ssl-cert-snakeoil.pem")
    -d	Disable Nigle's algorithm on TCP connections
    -f	Force MPIN authentication.
    -h	Output log by hex
    -key string
    	Path to certificate key file (default "/etc/ssl/private/ssl-cert-snakeoil.key")
    -l string
    	Local hostname:port (default ":3389")
    -m string
    	MPIN Server URL (default "https://public.milagro.io/mpinAuthenticate")
    -n string
    	ServerName (default "ldap.example.com")
    -p	Output profile. May not work on OSX.
    -r string
    	Remote hostname:port (default "localhost:389")
    -rs
    	Remote Enable TLS
    -s	Local Enable TLS
    -t	Test mode.  MPIN authentication is simulated.
    -v	Verbose mode
    -vv    	Ultra Verbose mode.  Be careful, this mode can log passwords.

    
For example,
`proxy -r yourldapserver.example.com:389 -l :4389 -s -vv`.

Please use nohup or daemonize or something else if you want use this proxy as a network daemon.

## How to work with Active Directory
 You can use AD LDS as the remote LDAP server by specifying baseDN.  userPrincipalName in simple bind request will work as the identity for MPIN authentication with this formula for example.  
 
  
  
    ./proxy -r 10.0.0.1:50000 -l :50389 -bindDN "cn=testreader,dc=test" -bindPWD "readerpass" -baseDN "DC=test"

Typically you will also need to specify bindDN and bindPWD, since AD LDS requires binding for user search functions by default.

## How to test?
Just run 

    bash test_full.sh
It will test asn.1-ber library and the proxy using LDAP server library in ldap/ as the local LDAP server.  If you are running the test on OS X, then you will need to increase the number of max openfiles and that of max sockets.

    ulimit -n 2048
    sysctl -w kern.ipc.somaxconn=2048


To test the LDAP server library, go to ldap/ and run

    go test -v
    
    
## TODO

We need to refactor the channels for cancellation.
