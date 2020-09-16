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

package env

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"time"

	"github.com/chiradeep/go-nitro/config/dns"
	"github.com/chiradeep/go-nitro/netscaler"
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/api/v2/endpoint"
	listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	hcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	tcm "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	"github.com/envoyproxy/go-control-plane/pkg/conversion"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	duration "github.com/golang/protobuf/ptypes/duration"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	"github.com/txn2/txeh"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/networking/util"
	authn_model "istio.io/istio/pilot/pkg/security/model"
	proto "istio.io/istio/pkg/proto"
)

const EnvoyTLSSocketName = "envoy.transport_sockets.tls"

func GetNetscalerIP() string {
	return os.Getenv("NS_TEST_IP")
}

func GetNetscalerURL() string {
	return "http://" + GetNetscalerIP() + ":" + os.Getenv("NS_TEST_NITRO_PORT")
}

func GetNetscalerUser() string {
	return os.Getenv("NS_TEST_LOGIN")
}

func GetNetscalerPassword() string {
	cpxpassfile := "/var/deviceinfo/random_id"
	if _, err := os.Stat(cpxpassfile); err == nil {
		pass, err := ioutil.ReadFile(cpxpassfile)
		if err == nil {
			return string(pass)
		}
	}
	return os.Getenv("NS_TEST_PASSWORD")
}

func GetNitroClient() *netscaler.NitroClient {
	return netscaler.NewNitroClient(GetNetscalerURL(), GetNetscalerUser(), GetNetscalerPassword())
}

func ClearNetscalerConfig() {
	client := GetNitroClient()
	client.ClearConfig()
	fmt.Println("Cleared netscaler config")
}

func getNameServer() (string, error) {
	b, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")
	match := re.FindString(string(b))
	return match, nil
}

func ConfigureDNS() error {
	nameserver, err := getNameServer()
	if err != nil {
		return err
	}
	client := GetNitroClient()
	_, err = client.AddResource(netscaler.Dnsnameserver.Type(), "", &dns.Dnsnameserver{Ip: nameserver})
	return err
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

func Init() {
	client := GetNitroClient()
	for {
		_, err := client.FindFilteredResourceArray(netscaler.Nsip.Type(), map[string]string{"type": "NSIP"})
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	client.ClearConfig()
	fmt.Println("Netscaler is ready")
}

func AddHostToHostFile(ip string, hostName string, hostNames []string) error {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	if hostName != "" {
		hosts.AddHost(ip, hostName)
	}
	if hostNames != nil {
		hosts.AddHosts(ip, hostNames)
	}

	hosts.Save()
	fmt.Printf("Host render file:\n")
	hfData := hosts.RenderHostsFile()
	fmt.Println(hfData)
	fmt.Printf("/etc/hosts:\n")
	file, errf := os.Open("/etc/hosts")
	if errf != nil {
		fmt.Printf("File open failed - %v", err)
	} else {
		b, _ := ioutil.ReadAll(file)
		fmt.Print("___________________________________\n")
		fmt.Print(string(b))
		file.Close()
	}
	return nil
}

func RemoveAddressFromHostFile(ip string) error {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return err
	}
	hosts.RemoveAddress(ip)
	hosts.Save()
	return nil
}

type ServiceEndpoint struct {
	IP     string
	Port   int
	Weight uint32
}

func MakeEndpoint(clusterName string, serviceEndpoints []ServiceEndpoint) *xdsapi.ClusterLoadAssignment {
	lbEndpoints := make([]*endpoint.LbEndpoint, 0)
	for _, ep := range serviceEndpoints {
		lbEndpoint := endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol:      core.SocketAddress_TCP,
								Address:       ep.IP,
								PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(ep.Port)},
							},
						},
					},
				},
			},
			LoadBalancingWeight: &wrappers.UInt32Value{
				Value: ep.Weight,
			},
		}
		lbEndpoints = append(lbEndpoints, &lbEndpoint)
	}
	return &xdsapi.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{
			&endpoint.LocalityLbEndpoints{
				LbEndpoints: lbEndpoints,
			},
		},
	}
}

func MakeCluster(clusterName string) *xdsapi.Cluster {
	var to duration.Duration = duration.Duration{Seconds: 1}
	return &xdsapi.Cluster{
		Name:           clusterName,
		ConnectTimeout: &to,
		ClusterDiscoveryType: &xdsapi.Cluster_Type{
			Type: xdsapi.Cluster_EDS,
		},
		LbPolicy: xdsapi.Cluster_ROUND_ROBIN,
		EdsClusterConfig: &xdsapi.Cluster_EdsClusterConfig{
			ServiceName: clusterName,
		},
	}
}

func MakeClusterDNS(clusterName string, dns string, port int) *xdsapi.Cluster {
	var to duration.Duration = duration.Duration{Seconds: 1}
	return &xdsapi.Cluster{
		Name:           clusterName,
		ConnectTimeout: &to,
		ClusterDiscoveryType: &xdsapi.Cluster_Type{
			Type: xdsapi.Cluster_STRICT_DNS,
		},
		LoadAssignment: MakeEndpoint(clusterName, []ServiceEndpoint{{IP: dns, Port: port, Weight: 1}}),
	}
}

type RouteInfo struct {
	Domain      string
	ClusterName string
}

func MakeRoute(routeName string, routes []RouteInfo) *xdsapi.RouteConfiguration {
	vHosts := make([]*route.VirtualHost, 0)
	for index, inpRoute := range routes {
		vroute := route.VirtualHost{
			Name:    fmt.Sprintf("route-%v", index),
			Domains: []string{inpRoute.Domain},
			Routes: []*route.Route{
				&route.Route{
					Name:  "default",
					Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
					Action: &route.Route_Route{
						Route: &route.RouteAction{
							ClusterSpecifier: &route.RouteAction_Cluster{Cluster: inpRoute.ClusterName},
						},
					},
				},
			},
		}
		vHosts = append(vHosts, &vroute)
	}
	return &xdsapi.RouteConfiguration{
		Name:         routeName,
		VirtualHosts: vHosts,
	}
}

func MakeListener(listenerName string, ip string, port uint16, filter *listener.Filter) (*xdsapi.Listener, error) {
	return &xdsapi.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: []*listener.FilterChain{
			&listener.FilterChain{
				Filters: []*listener.Filter{filter},
			},
		},
	}, nil
}

func MakeListenerFilterChains(listenerName string, ip string, port uint16, filterChains []*listener.FilterChain) *xdsapi.Listener {
	l, _ := MakeListener(listenerName, ip, port, nil)
	l.FilterChains = filterChains
	return l
}

func MakeTcpFilter(listenerName string, clusterName string) (*listener.Filter, error) {
	filterTCPListenerS := &tcm.TcpProxy{
		StatPrefix: listenerName,
		ClusterSpecifier: &tcm.TcpProxy_Cluster{
			Cluster: clusterName,
		},
	}
	filterTCPListener, err := conversion.MessageToStruct(filterTCPListenerS)
	if err != nil {
		return nil, err
	}
	return &listener.Filter{
		Name: xdsutil.TCPProxy,
		ConfigType: &listener.Filter_Config{
			Config: filterTCPListener,
		},
	}, nil
}

func MakeTcpListener(listenerName string, ip string, port uint16, clusterName string) (*xdsapi.Listener, error) {
	filter, err := MakeTcpFilter(listenerName, clusterName)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, filter)
}

func MakeFilterChain(prefix string, prefixLen uint32, port uint32, filterChainName string, filter *listener.Filter) *listener.FilterChain {
	return &listener.FilterChain{
		Name:    filterChainName,
		Filters: []*listener.Filter{filter},
		FilterChainMatch: &listener.FilterChainMatch{
			DestinationPort: &wrappers.UInt32Value{Value: port},
			PrefixRanges:    []*core.CidrRange{{AddressPrefix: prefix, PrefixLen: &wrappers.UInt32Value{Value: prefixLen}}},
		},
	}
}

func MakeHttpFilter(listenerName string, routeName string, route *xdsapi.RouteConfiguration) (*listener.Filter, error) {
	filterHTTPConnS := &hcm.HttpConnectionManager{
		StatPrefix:  listenerName,
		HttpFilters: []*hcm.HttpFilter{{Name: xdsutil.Router}},
	}
	if route != nil {
		filterHTTPConnS.RouteSpecifier = &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: route}
	} else if routeName != "" {
		filterHTTPConnS.RouteSpecifier = &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{RouteConfigName: routeName}}
	}
	filterHTTPConn, err := conversion.MessageToStruct(filterHTTPConnS)
	if err != nil {
		return nil, err
	}
	filter := listener.Filter{
		Name: "envoy.http_connection_manager",
		ConfigType: &listener.Filter_Config{
			Config: filterHTTPConn,
		},
	}
	return &filter, nil
}

func MakeHttpListener(listenerName string, ip string, port uint16, routeName string) (*xdsapi.Listener, error) {
	filter, err := MakeHttpFilter(listenerName, routeName, nil)
	if err != nil {
		return nil, err
	}
	return MakeListener(listenerName, ip, port, filter)
}

func MakeTLSContext(certFile, keyFile, rootFile string, inline bool) *auth.CommonTlsContext {
	tlsContext := &auth.CommonTlsContext{}
	if inline == false {
		if certFile != "" {
			tlsContext.TlsCertificates = []*auth.TlsCertificate{{
				CertificateChain: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: certFile}},
				PrivateKey:       &core.DataSource{Specifier: &core.DataSource_Filename{Filename: keyFile}},
			}}
		}
		if rootFile != "" {
			tlsContext.ValidationContextType = &auth.CommonTlsContext_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{Specifier: &core.DataSource_Filename{Filename: rootFile}},
				},
			}
		}
	} else {
		if certFile != "" {
			certData, _ := ioutil.ReadFile(certFile)
			keyData, _ := ioutil.ReadFile(keyFile)
			tlsContext.TlsCertificates = []*auth.TlsCertificate{{
				CertificateChain: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(certData)}},
				PrivateKey:       &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(keyData)}},
			}}
		}
		if rootFile != "" {
			rootCertData, _ := ioutil.ReadFile(rootFile)
			tlsContext.ValidationContextType = &auth.CommonTlsContext_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: string(rootCertData)}},
				},
			}
		}
	}
	return tlsContext
}

func CreateSDSTlsStreamSDS() *auth.CommonTlsContext {
	return &auth.CommonTlsContext{
		TlsCertificateSdsSecretConfigs: []*auth.SdsSecretConfig{
			{
				Name: "default",
				SdsConfig: &core.ConfigSource{
					InitialFetchTimeout: features.InitialFetchTimeout,
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType: core.ApiConfigSource_GRPC,
							GrpcServices: []*core.GrpcService{
								{
									TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
										EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: authn_model.SDSClusterName},
									},
								},
							},
						},
					},
				},
			},
		},
		ValidationContextType: &auth.CommonTlsContext_CombinedValidationContext{
			CombinedValidationContext: &auth.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: &auth.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{})},
				ValidationContextSdsSecretConfig: &auth.SdsSecretConfig{
					Name: "ROOTCA",
					SdsConfig: &core.ConfigSource{
						InitialFetchTimeout: features.InitialFetchTimeout,
						ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
							ApiConfigSource: &core.ApiConfigSource{
								ApiType: core.ApiConfigSource_GRPC,
								GrpcServices: []*core.GrpcService{
									{
										TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
											EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: authn_model.SDSClusterName},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		AlpnProtocols: []string{"h2", "http/1.1"},
	}

}
func MakeHttpsListener(listenerName string, ip string, port uint16, routeName string, certFile, keyFile, rootFile string, clientAuth, useTransportSocket, inline, sds bool) (*xdsapi.Listener, error) {
	lds, err := MakeHttpListener(listenerName, ip, port, routeName)
	if err != nil {
		return nil, err
	}
	commonTlsContext := MakeTLSContext(certFile, keyFile, rootFile, inline)
	downStreamTlsContext := auth.DownstreamTlsContext{CommonTlsContext: commonTlsContext, RequireClientCertificate: &wrappers.BoolValue{Value: clientAuth}}
	if useTransportSocket == true {
		if sds == true {
			sdsTlsContext := &auth.DownstreamTlsContext{
				CommonTlsContext:         CreateSDSTlsStreamSDS(),
				RequireClientCertificate: proto.BoolTrue,
			}
			lds.FilterChains[0].TransportSocket = &core.TransportSocket{Name: util.EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: util.MessageToAny(sdsTlsContext)}}
		} else {
			lds.FilterChains[0].TransportSocket = &core.TransportSocket{Name: util.EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: util.MessageToAny(&downStreamTlsContext)}}
		}
	} else {
		lds.FilterChains[0].TlsContext = &downStreamTlsContext
	}
	return lds, nil
}

func MakeTcpSslListener(listenerName string, ip string, port uint16, clusterName string, certFile, keyFile, rootFile string, clientAuth bool) (*xdsapi.Listener, error) {
	lds, err := MakeTcpListener(listenerName, ip, port, clusterName)
	if err != nil {
		return nil, err
	}
	commonTlsContext := MakeTLSContext(certFile, keyFile, rootFile, false)
	lds.FilterChains[0].TlsContext = &auth.DownstreamTlsContext{CommonTlsContext: commonTlsContext, RequireClientCertificate: &wrappers.BoolValue{Value: clientAuth}}
	return lds, nil
}

type SniInfo struct {
	ServerName  string
	CertFile    string
	KeyFile     string
	RootFile    string
	RouteName   string
	ClusterName string
}

func MakeHttpsSniListener(listenerName string, ip string, port uint16, sniInfos []SniInfo, transportSocket, inline bool) (*xdsapi.Listener, error) {
	filterChains := make([]*listener.FilterChain, 0)
	for _, sniInfo := range sniInfos {
		filter, err := MakeHttpFilter(listenerName, sniInfo.RouteName, nil)
		if err != nil {
			return nil, err
		}
		tlsContext := &auth.DownstreamTlsContext{CommonTlsContext: MakeTLSContext(sniInfo.CertFile, sniInfo.KeyFile, sniInfo.RootFile, inline)}
		var filterChain listener.FilterChain
		if transportSocket == false {
			filterChain = listener.FilterChain{
				Filters:          []*listener.Filter{filter},
				TlsContext:       tlsContext,
				FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
			}
		} else {
			filterChain = listener.FilterChain{
				Filters:          []*listener.Filter{filter},
				TransportSocket:  &core.TransportSocket{Name: util.EnvoyTLSSocketName, ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: util.MessageToAny(tlsContext)}},
				FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
			}

		}
		filterChains = append(filterChains, &filterChain)
	}
	return &xdsapi.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: filterChains,
	}, nil
}

func MakeTcpSniListener(listenerName string, ip string, port uint16, sniInfos []SniInfo) (*xdsapi.Listener, error) {
	filterChains := make([]*listener.FilterChain, 0)
	for _, sniInfo := range sniInfos {
		filter, err := MakeTcpFilter(listenerName, sniInfo.ClusterName)
		if err != nil {
			return nil, err
		}
		filterChain := listener.FilterChain{
			Filters:          []*listener.Filter{filter},
			FilterChainMatch: &listener.FilterChainMatch{ServerNames: []string{sniInfo.ServerName}},
		}
		filterChains = append(filterChains, &filterChain)
	}
	return &xdsapi.Listener{
		Name: listenerName,
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Address:       ip,
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: uint32(port)}}}},
		FilterChains: filterChains,
	}, nil
}
