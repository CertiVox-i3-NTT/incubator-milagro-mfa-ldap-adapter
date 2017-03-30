package main

import (
	"regexp"
	"net/http"
	"encoding/json"
	"bytes"
	"io/ioutil"

	//"gopkg.in/asn1-ber.v1"
	"github.com/CertiVox-i3-NTT/asn1-ber"
	//"gopkg.in/ldap.v2"
	"github.com/CertiVox-i3-NTT/ldap"
	"strings"
	"time"
	"math/rand"
)


// Finish overriding Bind request, by forwarding bind request in buf to Remote,
// or creating response packet with messageID and resultCode and sending to Local.
// p.forwardBind decides which should occur.
func (p *proxy) postprocessBindRequest(packet *ber.Packet, outbound chan *ber.Packet, messageID int64, resultCode uint8) *ber.Packet {
	if p.forwardBind && packet != nil {
		return packet
	} else if outbound != nil {
		if messageID >= 0 {  // MessageID ::= INTEGER(0.. maxInt), maxInt INTEGER ::= 2^31-1
			responsePacket := encodeBindResponse(messageID, resultCode)
			defer func(){recover()}()  // do not panic if outbound is closed
			outbound <- responsePacket
			return nil
		} else {
			return packet
		}
	}
	return nil
}

// analyzer for L to R.  outbound is out going channel for aux packets
func (p *proxy) analyzerIncomingLDAP(packet *ber.Packet, outbound chan *ber.Packet) *ber.Packet {
	//packet, err := ber.ReadPacket(bytes.NewBuffer(buf))
	if packet == nil {
		return nil
	}

	if outbound == nil {
		return packet
	}

	//ber.PrintPacket(packet)
	// sanity check this packet
	if len(packet.Children) < 2 {
		p.errLog(" len(packet.Children) < 2")
		return nil
	}

	// check the message ID and ClassType
	messageID, ok := packet.Children[0].Value.(int64)
	if !ok {
		p.errLog(" malformed messageID")
		return nil
	}
	req := packet.Children[1]
	if req.ClassType != ber.ClassApplication {
		p.errLog(" req.ClassType != ber.ClassApplication")
		return nil
	}

	/*
		// handle controls if present
		controls := []ldap.Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				controls = append(controls, ldap.DecodeControl(child))
			}
		}
	*/

	//if BindRequest, then check pwd whether it matches the exception rule. If matched, then discard it and return BindResponse with Success
	if req.Tag == ldap.ApplicationBindRequest {
		boundDN := req.Children[1].Data
		boundPWD := req.Children[2].Data

		if m, _ := regexp.MatchString("^{MPIN}", boundPWD.String()); m {



			// MPIN Authentication
			// post AuthOTT to /authentication API at mpinServerURL.
			type mpinToken struct{
				Version string  `json:"version"`
				AuthOTT string  `json:"authOTT"`
				Pass int `json:"pass"`
			}

			type authToken struct {
				MpinResponse mpinToken `json:"mpinResponse"`
			}

			type AuthResponse struct {
				Status  string	`json:"status"`
				Message string	`json:"message"`
				UserId  string	`json:"userId"`
				MpinId  string	`json:"mpinId"`
			}


			// Analyze DN to get uid.  If analyze fails, then forward it to the remote LDAP server.
			var bindRequestUid string
			dn, err := ldap.ParseDN(boundDN.String())
			if err != nil {
				p.warnLog("%s DN Parse failed.", boundDN.String())
				// Assume simple authentication for Active Directory
				// where boundDN is UPN
				// TODO Check UPN format
				if *baseDN == "" {
					return packet
				}
				p.ldapConnect()
				searchRequest := ldap.NewSearchRequest(*baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 600, true, "(" + ldap.EscapeFilter( *attributeName+"="+ boundDN.String()) + ")", nil, nil)
				result, err := p.ldapSearch(searchRequest)
				if err != nil || len(result.Entries) == 0 {
					// User not found
					p.errLog("%s DN Parse failed. LDAP Search Result : No Such Object.", boundDN.String())
					responsePacket := encodeBindResponse(messageID, ldap.LDAPResultNoSuchObject)
					outbound <- responsePacket
					return nil
				}
				bindRequestUid = boundDN.String()
			} else {
				// Assume DN is given as standardized
				// Then find uid
				for _, rdn := range dn.RDNs {
					for _, attribute := range rdn.Attributes {
						if strings.ToLower(attribute.Type) == "uid" {
							bindRequestUid = attribute.Value
						}
					}
				}

				// If attribute uid is not found, then throw the query to the remote LDAP server
				if bindRequestUid == "" {
					return packet
				}

				// Check if the requested user exists on the remote LDAP server.  If not fond, then reject bind request.
				p.ldapConnect()
				searchRequest := ldap.NewSearchRequest(boundDN.String(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 600, true, "(objectClass=*)", nil, nil)
				result, err := p.ldapSearch(searchRequest)
				if err != nil || len(result.Entries) == 0 {
					// User not found
					p.errLog("%s DN Parse successed. LDAP Search Result : No Such Object.", bindRequestUid)
					responsePacket := encodeBindResponse(messageID, ldap.LDAPResultNoSuchObject)
					outbound <- responsePacket
					return nil
				}
			}

			// prepare query to RPA
			var token authToken
			//token.MpinResponse = &mpinToken{}
			token.MpinResponse.AuthOTT = (boundPWD.String())[len("{MPIN}"):]  // trim {MPIN}
			token.MpinResponse.Pass = 2
			token.MpinResponse.Version= "0.3"

			// Check cache before asking to RPA
			if value, exists :=p.bindCache.Get(bindRequestUid); exists {
				//if *testmode {
				//	time.Sleep(500 * time.Millisecond + time.Duration(rand.Intn(500)) * time.Millisecond)
				//}
				if value == token.MpinResponse.AuthOTT {
					p.infoLog("%s MPIN authenticated.", bindRequestUid)
					return p.postprocessBindRequest(nil, outbound, messageID, ldap.LDAPResultSuccess)
				}
			}

			input, err := json.Marshal(token)
			if err != nil {
				p.errLog("%s json err: %v", bindRequestUid, err)
			}

			var resp *http.Response
			var body []byte
			var response = AuthResponse{}

			if *testmode {
				resp = &http.Response{StatusCode:http.StatusOK}
				response.UserId = bindRequestUid
				time.Sleep(500*time.Millisecond + time.Duration(rand.Intn(500))*time.Millisecond)
			}else {
				p.infoLog("%s Start MPIN authentication.", bindRequestUid)
				if *caCertFile == "" {
					resp, err = http.Post(*mpinServerAddr, "application/json", bytes.NewBuffer(input))
				} else {
					transport := &http.Transport{TLSClientConfig: &p.tlsConfig}
					client := &http.Client{Transport: transport}
					resp, err = client.Post(*mpinServerAddr, "application/json", bytes.NewBuffer(input))
				}
				if err != nil {
					p.errLog("%s %v", bindRequestUid, err)
					return p.postprocessBindRequest(packet, outbound, messageID, ldap.LDAPResultInvalidCredentials)
				}

				body, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					p.errLog("%s %v", bindRequestUid, err.Error())
					return p.postprocessBindRequest(packet, outbound, messageID, ldap.LDAPResultInvalidCredentials)
				}

				err = json.Unmarshal(body, &response)
				if err != nil {
					p.errLog("%s %v", bindRequestUid, err.Error())
					return p.postprocessBindRequest(packet, outbound, messageID, ldap.LDAPResultInvalidCredentials)
				}
			}

			if resp.StatusCode == http.StatusOK {
				p.infoLog("%s MPIN authenticated.", bindRequestUid)

				//ID check between service and MPIN
				if strings.ToLower(response.UserId) == strings.ToLower(bindRequestUid) {
					// store successful credential to cache
					p.bindCache.Set(bindRequestUid, token.MpinResponse.AuthOTT)

					p.infoLog("%s LDAPServer authenticated.", bindRequestUid)

					// say yes to bind request
					return p.postprocessBindRequest(nil, outbound, messageID, ldap.LDAPResultSuccess)
				}
			} else {
				p.errLog("%s MPIN Server: %s", bindRequestUid, body)
			}
		}
		return p.postprocessBindRequest(packet, outbound, messageID, ldap.LDAPResultStrongAuthRequired)
	}
	return packet
}

// generate successful BindResponse
func encodeBindResponse(messageID int64, ldapResultCode uint8) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultCode), "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	return responsePacket
}