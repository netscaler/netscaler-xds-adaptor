# Features supported according to Istio resources

The detailed list of fields supported on Citrix ADC as per the Istio CRDs (Destination Rule, Virtual Service, Policy, Gateway, Service Entry) is mentioned below.

## [Destination Rule](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/)

Destination rule allows you to define policies that apply to traffic intended for a service after routing has occurred.

The following table describes the destination rule settings supported by Citrix ADC with Istio.

| Field                                                      | Istio-adaptor version| 
|------------------------------------------------------------|---------------|
| [trafficPolicy.connectionPool.tcp.maxConnections](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-TCPSettings)          | 1.0.0 |
| [trafficPolicy.connectionPool.http.http2MaxRequests](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-HTTPSettings)       | 1.0.0 |
| [trafficPolicy.connectionPool.http.maxRequestsPerConnection](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-HTTPSettings) | 1.0.0 |
| [trafficPolicy.loadBalancer.simple = ROUND_ROBIN](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-SimpleLB)           | 1.0.0 | 
| [trafficPolicy.loadBalancer.simple = LEAST_CONN](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-SimpleLB)          | 1.0.0                     |
| [trafficPolicy.loadBalancer.simple = RANDOM](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-SimpleLB)               | 1.0.0          |
| [trafficPolicy.loadBalancer.consistentHash.httpHeaderName](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-ConsistentHashLB)  | 1.0.0  |
| [trafficPolicy.loadBalancer.consistentHash.httpCookie.name](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-ConsistentHashLB) | 1.0.0   |
| [trafficPolicy.loadBalancer.consistentHash.httpCookie.ttl](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-ConsistentHashLB-HTTPCookie)   |  1.0.0 |
| [trafficPolicy.loadBalancer.consistentHash.useSourceIp](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#LoadBalancerSettings-ConsistentHashLB)      | 1.0.0     |
| [trafficPolicy.tls.mode = DISABLE](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                          | 1.0.0  |
| [trafficPolicy.tls.mode = SIMPLE](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                         | 1.0.0   |
| [trafficPolicy.tls.mode = MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                           | 1.0.0    |
| [trafficPolicy.tls.mode = ISTIO_MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                      | 1.0.0           |
| [trafficPolicy.tls.clientCertificate](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                         | 1.0.0          |
| [trafficPolicy.tls.mode = MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                                 | 1.0.0         | [TLSSettings.TLSmode]                      |
| [trafficPolicy.tls.privateKey](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                               | 1.0.0   |
| [trafficPolicy.tls.caCertificates](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                           | 1.0.0           |
| [trafficPolicy.tls.sni](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                                      |  1.0.0         |
| [host](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#DestinationRule) | 1.0.0         |
| [subsets](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#Subset)    | 1.0.0      |

## [Virtual Service](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/)

Using virtual service, you can define a set of traffic routing rules to apply when a host is addressed.
The following table describes the virtual service configuration settings supported by Citrix ADC with Istio.

| Field                       | Istio-adaptor version |
|-----------------------------|---------------|
| [host](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                      | 1.0.0         |
| [subset](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                    | 1.0.0         |
| [port](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                        | 1.0.0         |
| [http.fault.abort.percentage](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPFaultInjection-Abort) | 1.0.0         |
| [http.fault.abort.httpStatus](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPFaultInjection-Abort) | 1.0.0          |
| [http.match.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)             | 1.0.0                 |
| [http.match.scheme](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 1.0.0                  |
| [http.match.method](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 1.0.0                  |
| [http.match.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)        | 1.0.0                  |
| [http.match.headers](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 1.0.0                |
| [http.match.port](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)            | 1.0.0                  |
| [http.redirect.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRedirect)           | 1.0.0                     |
| [http.redirect.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRedirect)     | 1.0.0                   |
| [http.rewrite.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRewrite)          | 1.0.0              |
| [http.rewrite.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRewrite)       | 1.0.0         |
| [tcp.route.destination](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#TCPRoute)         | 1.0.0         |
| [tcp.route.weight](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#TCPRoute)         | 1.0.0         |



## [Gateway](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/)

Gateway specification describes a set of ports that should be exposed, the type of protocol to use, SNI configuration for the load balancer, and so on. The following table describes the gateway configuration settings supported by Citrix ADC with Istio.

| Field                                 | Istio-adaptor version 
|---------------------------------------|---------------|
| [gateway.servers.port.number](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)          | 1.0.0         | 
| [gateway.servers.port.protocol](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)        | 1.0.0         |
| [gateway.servers.port.name](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)            | 1.0.0         |
| [gateway.servers.hosts](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server)     | 1.0.0         |              |
| [gateway.servers.tls.serverCertificate](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions) | 1.0.0         | 
| [gateway.servers.tls.privateKey](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)        | 1.0.0         |
| [gateway.servers.tls.caCertificates](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)    | 1.0.0         |
| [gateway.servers.tls.credentialName](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)   | 1.0.0 |
| [gateway.servers.tls.mode.SIMPLE](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions-TLSmode)       | 1.0.0  | 
| [gateway.servers.tls.mode.MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions-TLSmode)  | 1.0.0        |


## [Service Entry](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/)

You can use service entry to enable adding additional entries into Istio’s internal service registry. Once you enable it, auto-discovered services in the mesh can access or route to these manually specified services.

| Field                               | Istio-adaptor version | 
|-------------------------------------|-----------------------|
| [serviceentry.hosts](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)                | 1.0.0         | 
| [serviceentry.ports](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)               | 1.0.0         |
| [serviceentry.location.MESH_EXTERNAL](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Location) | 1.0.0         |
| [serviceentry.location.MESH_INTERNAL](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Location) | 1.0.0         |
| [serviceentry.resolution.DNS](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Resolution)       | 1.0.0         |
| [serviceentry.exportTo](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)  | 1.0.0 | 


## [Authentication Policy](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/)

Using authentication policies you can specify authentication requirements for services receiving requests in an Istio service mesh. The following table describes the authentication policy settings supported by Citrix ADC with Istio.

| Field                          | Istio-adaptor version| Remarks   |
|--------------------------------|----------------------|-----------| 
| [jwt](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#OriginAuthenticationMethod)| 1.0.0 |  |
| [jwt.issuer](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#OriginAuthenticationMethod) | 1.0.0 |  |
| [jwt.audiences](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt) | 1.0.0 |This feature is supported on Citrix ADC CPX 12.1-54, 13.0-38.13, and later versions.|
| [jwt.jwksUri](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt) | 1.0.0 |  |
| [jwt.jwtHeaders](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt) | 1.0.0  |This feature is supported on Citrix ADC CPX 12.1-54, 13.0-38.13, and later versions.|
| [jwt.jwtParams](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt)| 1.0.0 |This feature is supported on Citrix ADC CPX 12.1-54, 13.0-38.13, and later versions.|
| [jwt.triggerRules.excludedPaths](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) | 1.0.0 |  |
| [jwt.triggerRules.includedPaths](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) | 1.0.0 | |
| [mtls](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#PeerAuthenticationMethod) | 1.0.0  |    |
| [mutualtls.mode.strict](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#MutualTls-Mode) | 1.0.0 |  |



# Limitations

Citrix servicemesh solution currently does not support Mixer interaction. Thus, features associated with the Mixer are not supported. Citrix has plans to support Mixer integration in future releases.
