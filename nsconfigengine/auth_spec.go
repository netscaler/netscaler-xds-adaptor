/*
Copyright 2019 Citrix Systems, Inc
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nsconfigengine

import (
	"fmt"
	"github.com/chiradeep/go-nitro/config/authentication"
	"github.com/chiradeep/go-nitro/config/cs"
	"github.com/chiradeep/go-nitro/config/policy"
	"github.com/chiradeep/go-nitro/netscaler"
	"log"
	"strings"
)

const (
	dummyEndPoint = "https://dummy.com"
	maxLen        = 127
)

// AuthRuleMatch specifies an authentication match rule
type AuthRuleMatch struct {
	Exact  string
	Prefix string
	Suffix string
	Regex  string
}

// AuthSpec specifies the attributes associated with an authentication vserver
type AuthSpec struct {
	Name                   string
	IncludePaths           []AuthRuleMatch
	ExcludePaths           []AuthRuleMatch
	Issuer                 string
	JwksURI                string
	Audiences              []string
	JwtHeaders             []string
	JwtParams              []string
	curPolicyPriority      int
	curLoginSchemaPriority int
	FrontendTLS            []SSLSpec
}

func getAuthnRule(rules []AuthRuleMatch) string {
	authRules := make([]string, 0)
	for _, rule := range rules {
		if rule.Exact != "" {
			authRules = append(authRules, "HTTP.REQ.URL.EQ(\""+rule.Exact+"\")")
		} else if rule.Prefix != "" {
			authRules = append(authRules, "HTTP.REQ.URL.STARTSWITH(\""+rule.Prefix+"\")")
		} else if rule.Suffix != "" {
			authRules = append(authRules, "HTTP.REQ.URL.ENDSWITH(\""+rule.Suffix+"\")")
		} else if rule.Regex != "" {
			authRules = append(authRules, "HTTP.REQ.URL.REGEX_MATCH(re/"+rule.Regex+"/)")
		}
	}
	if len(authRules) == 0 {
		return ""
	}
	return "(" + strings.Join(authRules, " || ") + ")"
}

func addPatSet(client *netscaler.NitroClient, confErr *nitroError, authResourceName string, jwtAudiences []string) string {
	if len(jwtAudiences) > 0 {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Policypatset.Type(), authResourceName, policy.Policypatset{Name: authResourceName}, "add"}, nil, nil))
		for _, audience := range jwtAudiences {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Policypatset_pattern_binding.Type(), authResourceName, policy.Policypatsetpatternbinding{Name: authResourceName, String: audience}, "add"}, nil, nil))
		}
		return authResourceName
	}
	return ""
}

func getAuthAudience(jwtAudiences []string, nsReleaseNo float64, nsBuildNo float64) string {
	audiences := ""
	maxLength := maxLen
	for iter, audience := range jwtAudiences {
		temp := maxLength
		maxLength = maxLength - len(audience)
		if maxLength >= 0 {
			if audiences != "" && iter <= len(jwtAudiences) {
				audiences = audiences + "," + audience
			} else {
				audiences = audience
				if !((nsReleaseNo == 12.1 && nsBuildNo >= 53.3) || (nsReleaseNo == 13.0 && nsBuildNo >= 38.15)) {
					break
				}
			}
			maxLength = maxLength - 1
		} else {
			log.Printf("[ERROR] AudienceAdd : adding '%s' audience failed due to 127 char limit", audience)
			maxLength = temp
		}
	}
	return audiences
}

func (authSpec *AuthSpec) authAdd(client *netscaler.NitroClient, confErr *nitroError) {
	log.Printf("[TRACE] AuthSpec add: %v", authSpec)
	nsReleaseNo, nsBuildNo := getNsReleaseBuild()
	var audiences string
	if nsReleaseNo == 13.0 && nsBuildNo >= 41.10 {
		audiences = addPatSet(client, confErr, authSpec.Name, authSpec.Audiences)
	} else {
		audiences = getAuthAudience(authSpec.Audiences, nsReleaseNo, nsBuildNo)
	}
	/*	------------------------------------------------------------------------------------------------
		|	IncludePath	|	ExcludePath 	|	PolicyRule	|	ExcludeRule	|
		------------------------------------------------------------------------------------------------
		|       No		|	No		|	True		|	No		|
		------------------------------------------------------------------------------------------------
		|	/abc		|	No		|	/abc		|	True		|
		------------------------------------------------------------------------------------------------
		|	No		|	/xyz		|	!(/xyz)		|	/xyz		|
		------------------------------------------------------------------------------------------------
		|	/abc		|	/xyz		|	/abc		|	/xyz		|
		------------------------------------------------------------------------------------------------
	*/
	policyRule := ""
	excludeRule := ""
	loginSchemaRule := ""
	if len(authSpec.IncludePaths) == 0 && len(authSpec.ExcludePaths) == 0 {
		policyRule = "true"
	} else if len(authSpec.IncludePaths) > 0 && len(authSpec.ExcludePaths) == 0 {
		policyRule = getAuthnRule(authSpec.IncludePaths)
		excludeRule = "true"
	} else if len(authSpec.IncludePaths) == 0 && len(authSpec.ExcludePaths) > 0 {
		excludeRule = getAuthnRule(authSpec.ExcludePaths)
		policyRule = "(!" + excludeRule + ")"
	} else { // both IncludePaths and ExcludePaths are present
		policyRule = getAuthnRule(authSpec.IncludePaths)
		excludeRule = getAuthnRule(authSpec.ExcludePaths)
	}
	authSpec.curPolicyPriority = 10
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver.Type(), authSpec.Name, authentication.Authenticationvserver{Name: authSpec.Name, Servicetype: "SSL", Ipv46: "0.0.0.0"}, "add"}, nil, nil))
	authResourceName := authSpec.Name + "_" + fmt.Sprint(authSpec.curPolicyPriority)
	if audiences == "" {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationoauthaction.Type(), authResourceName, map[string]interface{}{"name": authResourceName, "audience": true}, "unset"}, nil, nil))
	}
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationoauthaction.Type(), authResourceName, authentication.Authenticationoauthaction{Name: authResourceName, Authorizationendpoint: dummyEndPoint, Tokenendpoint: dummyEndPoint, Clientid: "testcitrix", Clientsecret: "testcitrix", Issuer: authSpec.Issuer, Certendpoint: authSpec.JwksURI, Audience: audiences}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationpolicy.Type(), authResourceName, authentication.Authenticationpolicy{Name: authResourceName, Rule: policyRule, Action: authResourceName}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name, authentication.Authenticationvserverauthenticationpolicybinding{Name: authSpec.Name, Policy: authResourceName, Priority: authSpec.curPolicyPriority, Gotopriorityexpression: "NEXT"}, "add"}, []string{"A policy is already bound to the specified priority"}, nil))
	if excludeRule != "" {
		authSpec.curPolicyPriority = 20
		authResourceName := authSpec.Name + "_" + fmt.Sprint(authSpec.curPolicyPriority)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationpolicy.Type(), authResourceName, authentication.Authenticationpolicy{Name: authResourceName, Rule: excludeRule, Action: "NO_AUTHN"}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name, authentication.Authenticationvserverauthenticationpolicybinding{Name: authSpec.Name, Policy: authResourceName, Priority: authSpec.curPolicyPriority, Gotopriorityexpression: "NEXT"}, "add"}, []string{"A policy is already bound to the specified priority"}, nil))
	}
	for _, header := range authSpec.JwtHeaders {
		authSpec.curLoginSchemaPriority = authSpec.curLoginSchemaPriority + 10
		loginSchemaRule = "HTTP.REQ.HEADER(\"" + header + "\").EXISTS"
		if policyRule != "true" {
			loginSchemaRule = policyRule + " && " + loginSchemaRule
		}
		authResourceName := authSpec.Name + "_lgnschm_" + fmt.Sprint(authSpec.curLoginSchemaPriority)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschema.Type(), authResourceName, authentication.Authenticationloginschema{Name: authResourceName, Authenticationschema: "noschema", Userexpression: "HTTP.REQ.HEADER(\"" + header + "\")"}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschemapolicy.Type(), authResourceName, authentication.Authenticationloginschemapolicy{Name: authResourceName, Rule: loginSchemaRule, Action: authResourceName}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name, authentication.Authenticationvserverauthenticationpolicybinding{Name: authSpec.Name, Policy: authResourceName, Priority: authSpec.curLoginSchemaPriority, Gotopriorityexpression: "NEXT"}, "add"}, []string{"A policy is already bound to the specified priority"}, nil))
	}
	for _, param := range authSpec.JwtParams {
		authSpec.curLoginSchemaPriority = authSpec.curLoginSchemaPriority + 10
		loginSchemaRule = "HTTP.REQ.URL.QUERY.VALUE(\"" + param + "\").LENGTH.GT(0)"
		if policyRule != "true" {
			loginSchemaRule = policyRule + " && " + loginSchemaRule
		}
		authResourceName := authSpec.Name + "_lgnschm_" + fmt.Sprint(authSpec.curLoginSchemaPriority)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschema.Type(), authResourceName, authentication.Authenticationloginschema{Name: authResourceName, Authenticationschema: "noschema", Userexpression: "HTTP.REQ.URL.QUERY.VALUE(\"" + param + "\")"}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschemapolicy.Type(), authResourceName, authentication.Authenticationloginschemapolicy{Name: authResourceName, Rule: loginSchemaRule, Action: authResourceName}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name, authentication.Authenticationvserverauthenticationpolicybinding{Name: authSpec.Name, Policy: authResourceName, Priority: authSpec.curLoginSchemaPriority, Gotopriorityexpression: "NEXT"}, "add"}, []string{"A policy is already bound to the specified priority"}, nil))
	}
	addSSLVserver(client, authSpec.Name, authSpec.FrontendTLS, false, confErr)
	authSpec.deleteStale(client, confErr)
}

func (authSpec *AuthSpec) deletePatSet(client *netscaler.NitroClient, confErr *nitroError) {
	_, err := client.FindResource(netscaler.Policypatset.Type(), authSpec.Name)
	if err == nil {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Policypatset.Type(), authSpec.Name, nil, "delete"}, nil, nil))
	}
}

func (authSpec *AuthSpec) deleteStale(client *netscaler.NitroClient, confErr *nitroError) {
	log.Printf("[TRACE] AuthSpec deleteStale: %v", authSpec)
	var bvserverName, bPolicyName string
	var priority int
	authPolicyBindings, err := client.FindResourceArray(netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name)
	if err == nil {
		for _, authpolicyBinding := range authPolicyBindings {
			if bvserverName, err = getValueString(authpolicyBinding, "name"); err != nil {
				continue
			}
			if bPolicyName, err = getValueString(authpolicyBinding, "policy"); err != nil {
				continue
			}
			if priority, err = getValueInt(authpolicyBinding, "priority"); err != nil {
				continue
			}
			if priority <= authSpec.curPolicyPriority {
				continue
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationpolicy_binding.Type(), authSpec.Name, map[string]string{"name": bvserverName, "policy": bPolicyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationpolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationoauthaction.Type(), bPolicyName, nil, "delete"}, nil, nil))
		}
	}
	authPolicyBindings, err = client.FindResourceArray(netscaler.Authenticationvserver_authenticationloginschemapolicy_binding.Type(), authSpec.Name)
	if err == nil {
		for _, authpolicyBinding := range authPolicyBindings {
			if bvserverName, err = getValueString(authpolicyBinding, "name"); err != nil {
				continue
			}
			if bPolicyName, err = getValueString(authpolicyBinding, "policy"); err != nil {
				continue
			}
			if priority, err = getValueInt(authpolicyBinding, "priority"); err != nil {
				continue
			}
			if priority <= authSpec.curLoginSchemaPriority {
				continue
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver_authenticationloginschemapolicy_binding.Type(), authSpec.Name, map[string]string{"name": bvserverName, "policy": bPolicyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschemapolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationloginschema.Type(), bPolicyName, nil, "delete"}, nil, nil))
		}
	}
}

func (authSpec *AuthSpec) authDelete(client *netscaler.NitroClient, confErr *nitroError) {
	log.Printf("[TRACE] AuthSpec delete: %v", authSpec)
	authSpec.deleteStale(client, confErr)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Authenticationvserver.Type(), authSpec.Name, nil, "delete"}, []string{"No such resource"}, nil))
}

func updateVserverAuthSpec(client *netscaler.NitroClient, csVserverName string, authSpec *AuthSpec, confErr *nitroError) {
	log.Printf("[TRACE] updateVserverAuthSpec: %v for csVserver %s", authSpec, csVserverName)
	authVserverName := csVserverName + "authn"
	if authSpec == nil {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver.Type(), csVserverName, map[string]interface{}{"name": csVserverName, "authn401": true, "authnvsname": true}, "unset"}, nil, nil))
		authSpecD := &AuthSpec{Name: authVserverName}
		authSpecD.deletePatSet(client, confErr)
		authSpecD.authDelete(client, confErr)
	} else {
		authSpec.Name = authVserverName
		authSpec.deletePatSet(client, confErr)
		authSpec.authAdd(client, confErr)
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver.Type(), csVserverName, cs.Csvserver{Name: csVserverName, Authn401: "ON", Authnvsname: authSpec.Name}, "set"}, nil, nil))
	}
}
