package ldap

import (
	"bytes"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
	"errors"
)

var listenString = "127.0.0.1:3389"
var proxyString = "127.0.0.1:10389"
var proxyStringSSL = "127.0.0.1:14389"
var ldapURL = "ldap://" + proxyString
var ldapURLSSL = "ldaps://" + proxyStringSSL
var timeout = 1500 * time.Millisecond
var longerTimeout = 1500 * time.Millisecond
var wait = 1000 * time.Millisecond
var serverBaseDN = "o=testers,c=test"

/////////////////////////
func TestBindAnonOK(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindAnonFail(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	time.Sleep(timeout)
	quit <- true
}

/////////////////////////
func TestBindSimpleOK(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}


/////////////////////////
func TestBindSimpleUidOK(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimpleUid{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "uid=testy@example.com,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUidFailBadPw(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimpleUid{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "uid=testy@example.com,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUidOKAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUid{})
		s.BindFunc("", bindSimpleUid{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "uid=testy@example.com,"+serverBaseDN, "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUidFailAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidFail{})
		s.BindFunc("", bindSimpleUid{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "uid=testy@example.com,"+serverBaseDN, "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: No such object (32)") {
			t.Errorf("ldapsearch should have failed from NoSuchObject: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUidEmptyAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidEmpty{})
		s.BindFunc("", bindSimpleUid{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "uid=testy@example.com,"+serverBaseDN, "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: No such object (32)") {
			t.Errorf("ldapsearch should have failed from NoSuchObject: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}


/////////////////////////
func TestBindSimpleUPNOK(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()


	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "testy@example.com", "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUPNFailBadPw(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()


	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "testy@example.com", "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUPNFailBadID(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()


	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "nosuchuser@example.com", "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}


/////////////////////////
func TestBindSimpleUPNOKAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUid{})
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()


	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "testy@example.com", "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUPNFailAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidFail{})
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "testy@example.com", "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: No such object (32)") {
			t.Errorf("ldapsearch should have failed from NoSuchObject: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindSimpleUPNEmptyAuthOTT(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidEmpty{})
		s.BindFunc("", bindSimpleUPN{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-D", "testy@example.com", "-w", "{MPIN}xxx")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: No such object (32)") {
			t.Errorf("ldapsearch should have failed from NoSuchObject: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}



/////////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindLDAPS(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
//		time.Sleep(longerTimeout)
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 4):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}


/////////////////////////
func TestBindPanic(t *testing.T) {
	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindPanic{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	time.Sleep(wait)
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	quit := make(chan bool)
	done := make(chan bool)
	s := NewServer()

	go func() {
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		s.SetStats(true)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}

		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 { // Conns should be 2 because of ldap proxy
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}

	quit <- true
}

/////////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct {
}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimpleUid struct {
}

func (b bindSimpleUid) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	if bindDN == "uid=testy@example.com,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}

	return LDAPResultInvalidCredentials, nil
}

type bindSimpleUPN struct {
}

func (b bindSimpleUPN) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "testy@example.com" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}

	return LDAPResultInvalidCredentials, nil
}




type bindPanic struct {
}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	panic("test panic at the disco")
	return LDAPResultInvalidCredentials, nil
}

type searchSimple struct {
}

func (s searchSimple) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=ned,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"ned"}, nil},
			&EntryAttribute{"o", []string{"ate"}, nil},
			&EntryAttribute{"uidNumber", []string{"5000"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"ned"}, nil},
			&EntryAttribute{"description", []string{"ned via sa"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
		&Entry{"cn=trent,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"trent"}, nil},
			&EntryAttribute{"o", []string{"ate"}, nil},
			&EntryAttribute{"uidNumber", []string{"5005"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"trent"}, nil},
			&EntryAttribute{"description", []string{"trent via sa"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
		&Entry{"cn=randy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"randy"}, nil},
			&EntryAttribute{"o", []string{"ate"}, nil},
			&EntryAttribute{"uidNumber", []string{"5555"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"randy"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct {
}

func (s searchSimple2) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}, nil},
			&EntryAttribute{"o", []string{"testers"}, nil},
			&EntryAttribute{"uidNumber", []string{"5000"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"hamburger"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}


type searchSimpleUid struct {
}

func (s searchSimpleUid) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=testy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"testy"}, nil},
			&EntryAttribute{"o", []string{"ate"}, nil},
			&EntryAttribute{"uidNumber", []string{"5000"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"testy@example.com"}, nil},
			&EntryAttribute{"description", []string{"testy"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}


type searchSimpleUidFail struct {
}

func (s searchSimpleUidFail) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{nil, []string{}, []Control{}, LDAPResultNoSuchObject}, NewError(LDAPResultNoSuchObject, errors.New("Intentional Search error for test"))
}

type searchSimpleUidEmpty struct {
}

func (s searchSimpleUidEmpty) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{[]*Entry{}, []string{}, []Control{}, LDAPResultSuccess}, nil
}





type searchPanic struct {
}

func (s searchPanic) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	panic("this is a test panic")
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchControls struct {
}

func (s searchControls) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}, nil},
			&EntryAttribute{"o", []string{"testers"}, nil},
			&EntryAttribute{"uidNumber", []string{"5000"}, nil},
			&EntryAttribute{"accountstatus", []string{"active"}, nil},
			&EntryAttribute{"uid", []string{"hamburger"}, nil},
			&EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}
