/*
Copyright 2020 Citrix Systems, Inc
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
	"log"
	"net/http"
	"strings"

	"github.com/chiradeep/go-nitro/config/cs"
	"github.com/chiradeep/go-nitro/config/lb"
	"github.com/chiradeep/go-nitro/config/ns"
	"github.com/chiradeep/go-nitro/config/policy"
	"github.com/chiradeep/go-nitro/config/responder"
	"github.com/chiradeep/go-nitro/config/rewrite"
	"github.com/chiradeep/go-nitro/netscaler"
)

const (
	csPolicyStartPriority  = 10
	rwPolicyStartPriority  = 80
	resPolicyStartPriority = 10
	defaultMirrorWeight    = 100
	delayServerPort        = 10093
)

// CSApi specifies the attributes associated with a content switching vserver
type CSApi struct {
	Name                  string
	IP                    string
	Port                  int
	VserverType           string
	AllowACL              bool
	FrontendTLS           []SSLSpec
	FrontendTLSClientAuth bool
	DefaultLbVserverName  string
	SSLForwarding         []SSLForwardSpec
	AuthSpec              *AuthSpec
	AnalyticsProfileNames []string //AnalyticsProfileNames specifies analytics profiles (webinsight and tcpinsight) required for opentracing purpose
}

//RewriteAction will define members which will be used to rewrite policy
type RewriteAction struct {
	ActionType          string
	ActionTarget        string
	ActionStringBldrExp string
	Bindpoint           string
	Search              string
}

//CsPolicyBinding will define members which will be used to configure cs policy
type CsPolicyBinding struct {
	PolicyRules       []string
	TargetLB          string
	TargetVserverExpr string
	ServiceType       string
	WeightPercent     int
}

// NewCSApi returns a new CSApi object
func NewCSApi(name string, vserverType string, ip string, port int) *CSApi {
	csObj := new(CSApi)
	csObj.Name = name
	csObj.VserverType = vserverType
	csObj.IP = ip
	csObj.Port = port
	return csObj
}

// Add method creates/updates a CS vserver object on the Citrix-ADC
func (csObj *CSApi) Add(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] CSApi add: %s", GetLogString(csObj))
	confErr := newNitroError()
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver.Type(), csObj.Name, cs.Csvserver{Name: csObj.Name, Port: csObj.Port, Servicetype: csObj.VserverType, Ipv46: csObj.IP}, "add"}, nil, []nitroConfig{{netscaler.Csvserver.Type(), csObj.Name, nil, "delete"}, {netscaler.Csvserver.Type(), csObj.Name, cs.Csvserver{Name: csObj.Name, Port: csObj.Port, Servicetype: csObj.VserverType, Ipv46: csObj.IP}, "add"}}))
	if csObj.AllowACL == true {
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Nsacl.Type(), csObj.Name, ns.Nsacl{Aclname: csObj.Name, Aclaction: "ALLOW", Priority: csObj.Port, Protocol: "tcp", Destip: true, Destipval: csObj.IP, Destport: true, Destportval: fmt.Sprint(csObj.Port)}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Nsacls.Type(), "", ns.Nsacls{}, "apply"}, nil, nil))
		// AllowACL flag also indicates if this is an inbound cs vserver or not. Bind analyticsprofiles this cs vserver
		for _, profname := range csObj.AnalyticsProfileNames {
			confErr.updateError(doNitro(client, nitroConfig{"csvserver_analyticsprofile_binding", csObj.Name, map[string]string{"name": csObj.Name, "analyticsprofile": profname}, "add"}, nil, nil))
		}
	}
	if csObj.VserverType == "SSL" || csObj.VserverType == "SSL_TCP" {
		addSSLVserver(client, csObj.Name, csObj.FrontendTLS, csObj.FrontendTLSClientAuth, confErr)
	}
	if csObj.DefaultLbVserverName != "" {
		serviceType := "HTTP"
		if csObj.VserverType == "TCP" || csObj.VserverType == "SSL_TCP" {
			serviceType = "TCP"
		}
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), csObj.DefaultLbVserverName, lb.Lbvserver{Name: csObj.DefaultLbVserverName, Servicetype: serviceType}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_lbvserver_binding.Type(), csObj.Name, cs.Csvserverlbvserverbinding{Name: csObj.Name, Lbvserver: csObj.DefaultLbVserverName}, "add"}, nil, nil))
	}

	addSSLForwardSpec(client, csObj.Name, csObj.SSLForwarding, confErr)
	updateVserverAuthSpec(client, csObj.Name, csObj.AuthSpec, confErr)
	return confErr.getError()
}

// Delete method deletes a CS vserver
func (csObj *CSApi) Delete(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] CSApi delete: %v", csObj)
	confErr := newNitroError()
	addSSLForwardSpec(client, csObj.Name, []SSLForwardSpec{}, confErr)
	updateVserverAuthSpec(client, csObj.Name, csObj.AuthSpec, confErr)
	csBindings := NewCSBindingsAPI(csObj.Name)
	csBindings.deleteState(client, confErr)
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Nsacl.Type(), csObj.Name, nil, "delete"}, []string{"No such resource"}, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Nsacls.Type(), "", ns.Nsacls{}, "apply"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver.Type(), csObj.Name, nil, "delete"}, nil, nil))
	return confErr.getError()
}

// MatchHeader specifies a policy header match rule
type MatchHeader struct {
	Name   string
	Exact  string
	Prefix string
	Regex  string
}

// RouteMatch specifies a policy match rule
type RouteMatch struct {
	Domains []string
	Prefix  string
	Path    string
	Regex   string
	Headers []MatchHeader
}

func (match *RouteMatch) getMatchRule() string {
	matchRule := make([]string, 0)
	if match.getPolicyRuleForDomain() != "" {
		matchRule = append(matchRule, match.getPolicyRuleForDomain())
	}
	if match.Prefix != "" {
		matchRule = append(matchRule, "HTTP.REQ.URL.Startswith(\""+match.Prefix+"\")")
	}
	if match.Path != "" {
		matchRule = append(matchRule, "HTTP.REQ.URL.EQ(\""+match.Path+"\")")
	}
	if match.Regex != "" {
		matchRule = append(matchRule, "HTTP.REQ.URL.REGEX_MATCH(re/"+match.Regex+"/)")
	}
	for _, header := range match.Headers {
		if header.Exact != "" {
			matchRule = append(matchRule, "HTTP.REQ.HEADER(\""+header.Name+"\").EQ(\""+header.Exact+"\")")
		}
		if header.Prefix != "" {
			matchRule = append(matchRule, "HTTP.REQ.HEADER(\""+header.Name+"\").STARTSWITH(\""+header.Prefix+"\")")
		}
		if header.Regex != "" {
			matchRule = append(matchRule, "HTTP.REQ.HEADER(\""+header.Name+"\").REGEX_MATCH(re/"+header.Regex+"/)")
		}
	}
	if len(matchRule) == 0 {
		return "true"
	}
	return "(" + strings.Join(matchRule, " && ") + ")"
}

func (match *RouteMatch) getPolicyRuleForDomain() string {
	policyDomains := make([]string, 0)
	for _, domain := range match.Domains {
		if strings.Contains(domain, "*") {
			policyDomains = append(policyDomains, "HTTP.REQ.HOSTNAME.REGEX_MATCH(re/"+strings.Replace(domain, "*", ".*", -1)+"/)")
		} else {
			policyDomains = append(policyDomains, "HTTP.REQ.HOSTNAME.CONTAINS(\""+domain+"\")")
		}
	}
	if len(policyDomains) > 0 {
		return "(" + strings.Join(policyDomains, " || ") + ")"
	}
	return ""
}

// Fault specifies the fault testing to be introduced to the outbound traffic
type Fault struct {
	AbortPercent    int
	AbortHTTPStatus int
	DelayPercent    int
	DelaySeconds    int
}

// PersistencyPolicy speficies the persistency rules to be applied by an LB vserver entity while forwarding packets to backend services
type PersistencyPolicy struct {
	HeaderName string
	CookieName string
	Timeout    int
	SourceIP   bool
}

// Canary specifies a means of splitting traffic between one or more versions of a service
type Canary struct {
	LbVserverName     string
	LbVserverType     string
	TargetVserverExpr string
	Weight            int
	Persistency       *PersistencyPolicy
}

// CsPolicy specifies the LB vservers (including versions) to which the traffic is to be forwarded
type CsPolicy struct {
	Canary []Canary
}

// RwHeader specifes an HTTP header key and value
type RwHeader struct {
	Key   string
	Value string
}

// RewritePolicy specifies a rewrite operation to be made on an HTTP packet
type RewritePolicy struct {
	PrefixRewrite string
	HostRewrite   string
	AddHeaders    []RwHeader
}

// ResponderPolicy specifies how to respond to an HTTP request
type ResponderPolicy struct {
	RedirectHost string
	RedirectPath string
}

// HTTPCalloutPolicy sends HTTP request to
type HTTPCalloutPolicy struct {
	LbVserverName string
	ReturnType    string
	FullReqExpr   string
	ResultExpr    string
	IP            string
	Port          string
}

//HTTPMirror will mirror the traffic
type HTTPMirror struct {
	Callout *HTTPCalloutPolicy
	Weight  int
}

// CSBinding specifies the CS, RW or Responder action to be taken for a route match and the fault that needs to be introduced before taking the action
type CSBinding struct {
	Rule         RouteMatch
	Fault        Fault
	CsPolicy     CsPolicy
	RwPolicy     RewritePolicy
	ResPolicy    ResponderPolicy
	MirrorPolicy *HTTPMirror
}

//NewHTTPCalloutPolicy returns a NewHTTPCallout object
func NewHTTPCalloutPolicy(vserverName, returnType, fullReqExpr, IP, port, resultExpr string) *HTTPCalloutPolicy {
	calloutPolicy := new(HTTPCalloutPolicy)
	calloutPolicy.LbVserverName = vserverName
	calloutPolicy.ReturnType = returnType
	calloutPolicy.FullReqExpr = fullReqExpr
	calloutPolicy.ResultExpr = resultExpr
	calloutPolicy.IP = IP
	calloutPolicy.Port = port
	return calloutPolicy
}

//mirrorPolicyAdd adds the HTTP callout, rewrite policy and action required for HTTP mirror support
func (csBindings *CSBindingsAPI) mirrorPolicyAdd(client *netscaler.NitroClient, confErr *nitroError, callout *HTTPCalloutPolicy, policyName string) {
	expr := "http.req.header(\"host\").prefix(':', 0).append(\"-shadow:\").append(http.req.header(\"host\").after_str(\":\")).STRIP_END_CHARS(\":\")"
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Policyhttpcallout.Type(), policyName, policy.Policyhttpcallout{Name: policyName, Vserver: callout.LbVserverName, Returntype: callout.ReturnType, Resultexpr: callout.ResultExpr, Fullreqexpr: callout.FullReqExpr}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewriteaction.Type(), callout.LbVserverName, rewrite.Rewriteaction{Name: callout.LbVserverName, Type: "replace", Target: "HTTP.REQ.HEADER(\"HOST\")", Stringbuilderexpr: expr}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewritepolicy.Type(), callout.LbVserverName, rewrite.Rewritepolicy{Name: callout.LbVserverName, Rule: "true", Action: callout.LbVserverName}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver_rewritepolicy_binding.Type(), callout.LbVserverName, lb.Lbvserverrewritepolicybinding{Name: callout.LbVserverName, Policyname: callout.LbVserverName, Priority: rwPolicyStartPriority, Bindpoint: "REQUEST", Gotopriorityexpression: "NEXT"}, "add"}, nil, nil))
}

func mirrorPolicyDeleteWithLBvserver(client *netscaler.NitroClient, confErr *nitroError, policyName, vserver string) {
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Policyhttpcallout.Type(), policyName, nil, "delete"}, []string{"No such resource"}, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver_rewritepolicy_binding.Type(), vserver, map[string]string{"name": vserver, "policyname": vserver}, "delete"}, []string{"No such resource"}, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewritepolicy.Type(), vserver, nil, "delete"}, []string{"No such resource"}, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewriteaction.Type(), vserver, nil, "delete"}, []string{"No such resource"}, nil))
	lbObj := NewLBApi(vserver, "", "", "")
	lbObj.Delete(client)
}

func (csBindings *CSBindingsAPI) mirrorPolicyDelete(client *netscaler.NitroClient, confErr *nitroError, policyName string) {
	mirrorPolicy := GetNSCompatibleNameByLen(policyName+"_call_Mirror", 31)
	calloutPolicy, err := client.FindResourceArray(netscaler.Policyhttpcallout.Type(), mirrorPolicy)
	if err == nil {
		for _, callout := range calloutPolicy {
			vserver := callout["vserver"].(string)
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_cspolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": policyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Cspolicy.Type(), policyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csaction.Type(), policyName, nil, "delete"}, nil, nil))
			mirrorPolicyDeleteWithLBvserver(client, confErr, mirrorPolicy, vserver)
		}
	}
}

// CSBindingsAPI specifies the policies associated with a content switching vserver
type CSBindingsAPI struct {
	Name           string
	Bindings       []CSBinding
	curCsPriority  int
	curRwPriority  int
	curResPriority int
}

// NewCSBindingsAPI returns a new CSBindingAPI object
func NewCSBindingsAPI(name string) *CSBindingsAPI {
	csBindings := new(CSBindingsAPI)
	csBindings.Name = name
	csBindings.curCsPriority = csPolicyStartPriority
	csBindings.curRwPriority = rwPolicyStartPriority
	csBindings.curResPriority = resPolicyStartPriority
	return csBindings
}

func (csBindings *CSBindingsAPI) responderPolicyAdd(client *netscaler.NitroClient, confErr *nitroError, policyRule string, responseType string, responseTarget string, responseCode int) {
	responderEntityName := csBindings.Name + "_ra_" + fmt.Sprint(csBindings.curResPriority)
	responderAction := responder.Responderaction{Name: responderEntityName, Type: responseType, Target: responseTarget}
	if responseCode == 0 {
		responderAction.Responsestatuscode = responseCode
	}
	//Action update can fail if it is of different type. In this case unbind policy, delete policy, delete action and add action again
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Responderaction.Type(), responderEntityName, responderAction, "add"}, nil, []nitroConfig{
		{netscaler.Csvserver_responderpolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": responderEntityName}, "delete"},
		{netscaler.Responderpolicy.Type(), responderEntityName, nil, "delete"},
		{netscaler.Responderaction.Type(), responderEntityName, nil, "delete"},
		{netscaler.Responderaction.Type(), responderEntityName, responderAction, "add"}}))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Responderpolicy.Type(), responderEntityName, responder.Responderpolicy{Name: responderEntityName, Rule: policyRule, Action: responderEntityName}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_responderpolicy_binding.Type(), csBindings.Name, cs.Csvserverresponderpolicybinding{Name: csBindings.Name, Policyname: responderEntityName, Priority: csBindings.curResPriority, Gotopriorityexpression: "END"}, "add"}, nil, nil))
	csBindings.curResPriority = csBindings.curResPriority + 10
}

func (csBindings *CSBindingsAPI) rewritePolicyAdd(client *netscaler.NitroClient, confErr *nitroError, policyRule string, rewritepolinfo *RewriteAction) {
	rwEntityName := csBindings.Name + "_rw_" + fmt.Sprint(csBindings.curRwPriority)
	if rewritepolinfo.Search != "" {
		if strings.HasSuffix(rewritepolinfo.Search, "/") == true {
			policyRule = policyRule + " && http.req.url.contains(\"" + rewritepolinfo.Search + "\")"
			if rewritepolinfo.ActionStringBldrExp[0] == '/' {
				rewritepolinfo.ActionStringBldrExp = strings.TrimPrefix(rewritepolinfo.ActionStringBldrExp, "/")
			}
		} else {
			policyRule = policyRule + " && http.req.url.contains(\"" + rewritepolinfo.Search + "\") && http.req.url.contains(\"" + rewritepolinfo.Search + "/\").not"
		}
		rewritepolinfo.ActionStringBldrExp = "\"" + rewritepolinfo.ActionStringBldrExp + "\""
		rewritepolinfo.Search = "text(\"" + rewritepolinfo.Search + "\")"
	}
	// Action update can fail if it is of different type. In this case unbind policy, delete policy, delete action and add action again
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewriteaction.Type(), rwEntityName,
		rewrite.Rewriteaction{Name: rwEntityName, Type: rewritepolinfo.ActionType, Target: rewritepolinfo.ActionTarget, Stringbuilderexpr: rewritepolinfo.ActionStringBldrExp, Search: rewritepolinfo.Search}, "add"}, nil, []nitroConfig{
		{netscaler.Csvserver_rewritepolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": rwEntityName}, "delete"},
		{netscaler.Rewritepolicy.Type(), rwEntityName, nil, "delete"},
		{netscaler.Rewriteaction.Type(), rwEntityName, nil, "delete"},
		{netscaler.Rewriteaction.Type(), rwEntityName,
			rewrite.Rewriteaction{Name: rwEntityName, Type: rewritepolinfo.ActionType, Target: rewritepolinfo.ActionTarget, Stringbuilderexpr: rewritepolinfo.ActionStringBldrExp, Search: rewritepolinfo.Search}, "add"}}))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewritepolicy.Type(), rwEntityName, rewrite.Rewritepolicy{Name: rwEntityName, Rule: policyRule, Action: rwEntityName}, "add"}, nil, nil))
	confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_rewritepolicy_binding.Type(), csBindings.Name, cs.Csvserverrewritepolicybinding{Name: csBindings.Name, Policyname: rwEntityName, Priority: csBindings.curRwPriority, Gotopriorityexpression: "NEXT", Bindpoint: rewritepolinfo.Bindpoint}, "add"}, nil, nil))
	csBindings.curRwPriority = csBindings.curRwPriority + 10
}

func (csBindings *CSBindingsAPI) csPolicyAdd(client *netscaler.NitroClient, confErr *nitroError, csactpolinfo *CsPolicyBinding, persistency *PersistencyPolicy, mirror *HTTPMirror) {
	/* LBVserver ns_dummy_http is bound to CS Vserver for Redirect case where ResponderPolicy will be hit post selection of Vserver*/
	if (len(csactpolinfo.TargetLB) > 0) && csactpolinfo.TargetLB != "ns_dummy_http" {
		lbObj := lb.Lbvserver{Name: csactpolinfo.TargetLB, Servicetype: csactpolinfo.ServiceType, Persistencetype: "NONE", Timeout: 2}
		if persistency != nil {
			if persistency.HeaderName != "" {
				lbObj.Persistencetype = "RULE"
				lbObj.Rule = "HTTP.REQ.HEADER(\"" + persistency.HeaderName + "\")"
			} else if persistency.CookieName != "" {
				lbObj.Persistencetype = "COOKIEINSERT"
				lbObj.Cookiename = persistency.CookieName
				lbObj.Timeout = persistency.Timeout
			} else if persistency.SourceIP == true {
				lbObj.Persistencetype = "SOURCEIP"
			}
		}
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Lbvserver.Type(), csactpolinfo.TargetLB, lbObj, "add"}, nil, nil))
	}
	for _, policyRule := range csactpolinfo.PolicyRules {
		if policyRule == "" {
			continue
		}
		csBoundEntityName := csBindings.Name + "_" + fmt.Sprint(csBindings.curCsPriority)
		if csactpolinfo.WeightPercent != defaultMirrorWeight {
			policyRule = "(" + policyRule + " && sys.random.mul(100).lt(" + fmt.Sprint(csactpolinfo.WeightPercent) + "))"
		}
		mirrorCallout := GetNSCompatibleNameByLen(csBoundEntityName+"_call_Mirror", 31)
		if mirror != nil {
			csBindings.mirrorPolicyAdd(client, confErr, mirror.Callout, mirrorCallout)
			if mirror.Weight != 100 {
				/* TODO: Mirror Weight Support*/
			} else {
				policyRule = "(" + policyRule + " && (sys.non_blocking_http_callout(" + mirrorCallout + ")))"
			}
		} else {
			csBindings.mirrorPolicyDelete(client, confErr, csBoundEntityName)
		}
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Csaction.Type(), csBoundEntityName, cs.Csaction{Name: csBoundEntityName, Targetlbvserver: csactpolinfo.TargetLB, Targetvserverexpr: csactpolinfo.TargetVserverExpr}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Cspolicy.Type(), csBoundEntityName, cs.Cspolicy{Policyname: csBoundEntityName, Rule: policyRule, Action: csBoundEntityName}, "add"}, nil, nil))
		confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_cspolicy_binding.Type(), csBindings.Name, cs.Csvservercspolicybinding{Name: csBindings.Name, Policyname: csBoundEntityName, Priority: csBindings.curCsPriority}, "add"}, nil, nil))
		csBindings.curCsPriority = csBindings.curCsPriority + 10

	}
}

// Add method binds/updates policies to a CS vserver
func (csBindings *CSBindingsAPI) Add(client *netscaler.NitroClient) error {
	log.Printf("[TRACE] CSBindingsAPI add: %+v", csBindings)
	confErr := newNitroError()
	rewritepolinfo := new(RewriteAction)
	for _, csBinding := range csBindings.Bindings {
		curPolicyRule := csBinding.Rule.getMatchRule()
		curDelayRule := ""
		if csBinding.Fault.AbortPercent != 0 {
			csBindings.responderPolicyAdd(client, confErr, "(("+curPolicyRule+")"+" && sys.random.mul(100).lt("+fmt.Sprint(csBinding.Fault.AbortPercent)+"))", "respondwith", "\"HTTP/1.1 "+fmt.Sprint(csBinding.Fault.AbortHTTPStatus)+" "+http.StatusText(csBinding.Fault.AbortHTTPStatus)+"\r\n\r\n\"", 0)
		}
		bindingName := csBindings.Name + "_" + fmt.Sprint(csBindings.curCsPriority)
		httpCalloutName := GetNSCompatibleNameByLen(bindingName+"_call_Delay", 31)
		if csBinding.Fault.DelayPercent != 0 {
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Policyhttpcallout.Type(), httpCalloutName, policy.Policyhttpcallout{Name: httpCalloutName, Ipaddress: "192.0.0.2", Port: delayServerPort, Returntype: "TEXT", Hostexpr: "\"127.0.0.1\"", Urlstemexpr: "\"/?sleep=" + fmt.Sprint(csBinding.Fault.DelaySeconds) + "\"", Resultexpr: "http.res.body(100)"}, "add"}, nil, nil))
			curDelayRule = "(" + curPolicyRule + " && sys.random.mul(100).lt(" + fmt.Sprint(csBinding.Fault.DelayPercent) + ") && sys.http_callout(" + httpCalloutName + ").length.gt(0))"
		} else {
			_, err := client.FindResource(netscaler.Policyhttpcallout.Type(), httpCalloutName)
			if err == nil {
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_cspolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": bindingName}, "delete"}, nil, nil))
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Cspolicy.Type(), bindingName, nil, "delete"}, nil, nil))
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Csaction.Type(), bindingName, nil, "delete"}, nil, nil))
				confErr.updateError(doNitro(client, nitroConfig{netscaler.Policyhttpcallout.Type(), httpCalloutName, nil, "delete"}, nil, nil))
			}
		}
		rewritepolinfo.Bindpoint = "REQUEST"
		if csBinding.RwPolicy.PrefixRewrite != "" && csBinding.Rule.Prefix != "" {
			rewritepolinfo.ActionType = "replace_all"
			rewritepolinfo.ActionTarget = "http.REQ.URL"
			rewritepolinfo.ActionStringBldrExp = csBinding.RwPolicy.PrefixRewrite
			rewritepolinfo.Search = csBinding.Rule.Prefix
			csBindings.rewritePolicyAdd(client, confErr, curPolicyRule, rewritepolinfo)
		}
		if csBinding.RwPolicy.HostRewrite != "" {
			rewritepolinfo.ActionType = "replace"
			rewritepolinfo.ActionTarget = "HTTP.REQ.HOSTNAME"
			rewritepolinfo.ActionStringBldrExp = "\"" + csBinding.RwPolicy.HostRewrite + "\""
			rewritepolinfo.Search = ""
			csBindings.rewritePolicyAdd(client, confErr, curPolicyRule, rewritepolinfo)
		}

		for _, reqAddHeader := range csBinding.RwPolicy.AddHeaders {
			rewritepolinfo.ActionType = "insert_http_header"
			rewritepolinfo.ActionStringBldrExp = "\"" + csBinding.RwPolicy.HostRewrite + "\""
			rewritepolinfo.Search = ""
			rewritepolinfo.ActionTarget = reqAddHeader.Key
			rewritepolinfo.ActionStringBldrExp = "\"" + reqAddHeader.Value + "\""
			csBindings.rewritePolicyAdd(client, confErr, curPolicyRule, rewritepolinfo)
		}
		totalWeight := 0
		for _, canary := range csBinding.CsPolicy.Canary {
			totalWeight = totalWeight + canary.Weight
		}
		for _, canary := range csBinding.CsPolicy.Canary {
			weightPercentage := 100
			if canary.Weight != totalWeight {
				weightPercentage = (canary.Weight * 100) / totalWeight
			}
			csactpolinfo := new(CsPolicyBinding)
			csactpolinfo.PolicyRules = []string{curDelayRule, curPolicyRule}
			csactpolinfo.TargetLB = canary.LbVserverName
			csactpolinfo.ServiceType = canary.LbVserverType
			csactpolinfo.WeightPercent = weightPercentage
			csactpolinfo.TargetVserverExpr = canary.TargetVserverExpr
			csBindings.csPolicyAdd(client, confErr, csactpolinfo, canary.Persistency, csBinding.MirrorPolicy)
			totalWeight = totalWeight - canary.Weight
		}
		if csBinding.ResPolicy.RedirectHost != "" && csBinding.ResPolicy.RedirectPath != "" {
			csBindings.responderPolicyAdd(client, confErr, curPolicyRule, "redirect", "\"http://"+csBinding.ResPolicy.RedirectHost+csBinding.ResPolicy.RedirectPath+"\"", 301)
		} else if csBinding.ResPolicy.RedirectHost != "" {
			csBindings.responderPolicyAdd(client, confErr, curPolicyRule, "redirect", "\"http://"+csBinding.ResPolicy.RedirectHost+"\"+HTTP.REQ.URL", 301)
		} else if csBinding.ResPolicy.RedirectPath != "" {
			csBindings.responderPolicyAdd(client, confErr, curPolicyRule, "redirect", "HTTP.REQ.HOSTNAME + \""+csBinding.ResPolicy.RedirectPath+"\"", 301)
		}
	}
	csBindings.deleteState(client, confErr)
	return confErr.getError()
}

func (csBindings *CSBindingsAPI) deleteState(client *netscaler.NitroClient, confErr *nitroError) {
	var bPolicyName string
	var priority int

	log.Printf("[TRACE] CSBindingsAPI delete stale: %v", csBindings)
	csvserverRewritePolicyBindings, err := client.FindResourceArray(netscaler.Csvserver_rewritepolicy_binding.Type(), csBindings.Name)
	if err == nil {
		for _, csvserverRewritepolicyBinding := range csvserverRewritePolicyBindings {
			if bPolicyName, err = getValueString(csvserverRewritepolicyBinding, "policyname"); err != nil {
				continue
			}
			if priority, err = getValueInt(csvserverRewritepolicyBinding, "priority"); err != nil {
				continue
			}
			if priority < csBindings.curRwPriority {
				continue
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_rewritepolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": bPolicyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewritepolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Rewriteaction.Type(), bPolicyName, nil, "delete"}, nil, nil))
		}
	}

	csvserverCspolicyBindings, err := client.FindResourceArray(netscaler.Csvserver_cspolicy_binding.Type(), csBindings.Name)
	if err == nil {
		for _, csvserverCspolicyBinding := range csvserverCspolicyBindings {
			if bPolicyName, err = getValueString(csvserverCspolicyBinding, "policyname"); err != nil {
				continue
			}
			if priority, err = getValueInt(csvserverCspolicyBinding, "priority"); err != nil {
				continue
			}
			if priority < csBindings.curCsPriority {
				continue
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_cspolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": bPolicyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Cspolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csaction.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Policyhttpcallout.Type(), GetNSCompatibleNameByLen(bPolicyName+"_call_Delay", 31), nil, "delete"}, nil, nil))
			calloutPolicy, err := client.FindResource(netscaler.Policyhttpcallout.Type(), GetNSCompatibleNameByLen(bPolicyName+"_call_Mirror", 31))
			if err == nil {
				mirrorPolicyDeleteWithLBvserver(client, confErr, GetNSCompatibleNameByLen(bPolicyName+"_call_Mirror", 31), calloutPolicy["vserver"].(string))
			}
		}
	}

	csvserverResponderPolicyBindings, err := client.FindResourceArray(netscaler.Csvserver_responderpolicy_binding.Type(), csBindings.Name)
	if err == nil {

		for _, csvserverResponderPolicyBinding := range csvserverResponderPolicyBindings {
			if bPolicyName, err = getValueString(csvserverResponderPolicyBinding, "policyname"); err != nil {
				continue
			}
			if priority, err = getValueInt(csvserverResponderPolicyBinding, "priority"); err != nil {
				continue
			}
			if priority < csBindings.curResPriority {
				continue
			}
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Csvserver_responderpolicy_binding.Type(), csBindings.Name, map[string]string{"name": csBindings.Name, "policyname": bPolicyName}, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Responderpolicy.Type(), bPolicyName, nil, "delete"}, nil, nil))
			confErr.updateError(doNitro(client, nitroConfig{netscaler.Responderaction.Type(), bPolicyName, nil, "delete"}, nil, nil))
		}
	}
}
