# Features supported according to Istio resources

The detailed list of fields supported on Citrix ADC as per the Istio CRDs (Destination Rule, Virtual Service, Policy, Gateway, Service Entry) is specified as follows:

## [Destination Rule](https://istio.io/latest/docs/reference/config/networking/destination-rule/)

Destination rule allows you to define policies that apply to traffic intended for a service after routing has occurred.

The following table describes the destination rule settings supported by Citrix ADC with Istio.

| Field                                                      | xDS-adaptor version| Citrix ADC Version |
|------------------------------------------------------------|---------------|-----------------------|
| [trafficPolicy.connectionPool.tcp.maxConnections](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-TCPSettings)          | 0.9.5 | 13.0–37.16+  |
| [trafficPolicy.connectionPool.http.http2MaxRequests](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-HTTPSettings)       | 0.9.5 | 13.0–37.16+ | 
| [trafficPolicy.connectionPool.http.maxRequestsPerConnection](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#ConnectionPoolSettings-HTTPSettings) | 0.9.5 | 13.0–37.16+  |
| [trafficPolicy.loadBalancer.simple = ROUND_ROBIN](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-SimpleLB)           | 0.9.5 | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.simple = LEAST_CONN](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-SimpleLB)          | 0.9.5                     | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.simple = RANDOM](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-SimpleLB)               | 0.9.5          | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.consistentHash.httpHeaderName](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-ConsistentHashLB)  | 0.9.5  | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.consistentHash.httpCookie.name](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-ConsistentHashLB) | 0.9.5   | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.consistentHash.httpCookie.ttl](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-ConsistentHashLB-HTTPCookie)   |  0.9.5 | 13.0–37.16+  | 
| [trafficPolicy.loadBalancer.consistentHash.useSourceIp](https://istio.io/latest/docs/reference/config/networking/destination-rule/#LoadBalancerSettings-ConsistentHashLB)      | 0.9.5     | 13.0–37.16+  | 
| [trafficPolicy.tls.mode = DISABLE](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                          | 0.9.5  | 13.0–37.16+  | 
| [trafficPolicy.tls.mode = SIMPLE](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                         | 0.9.5   | 13.0–37.16+  | 
| [trafficPolicy.tls.mode = MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                           | 0.9.5    | 13.0–37.16+  | 
| [trafficPolicy.tls.mode = ISTIO_MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                      | 0.9.5           | 13.0–37.16+  | 
| [trafficPolicy.tls.clientCertificate](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                         | 0.9.5          | 13.0–37.16+  | 
| [trafficPolicy.tls.mode = MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings-TLSmode)                                 | 0.9.5         | 13.0–37.16+ |
| [trafficPolicy.tls.privateKey](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                               | 0.9.5   | 13.0–37.16+  | 
| [trafficPolicy.tls.caCertificates](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                           | 0.9.5           | 13.0–37.16+  | 
| [trafficPolicy.tls.sni](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#TLSSettings)                                      |  0.9.5         | 13.0–37.16+  | 
| [host](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#DestinationRule) | 0.9.5         | 13.0–37.16+  | 
| [subsets](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#Subset)    | 0.9.5      | 13.0–37.16+  | 


## [Virtual Service](https://istio.io/latest/docs/reference/config/networking/virtual-service/)

Using virtual service, you can define a set of traffic routing rules to apply when a host is addressed.
The following table describes the virtual service configuration settings supported by Citrix ADC with Istio.

| Field                       | xDS-adaptor version | Citrix ADC Version |
|-----------------------------|---------------|---------------------------|
| [host](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                      | 0.9.5         | 13.0–37.16+  | 
| [subset](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                    | 0.9.5         | 13.0–37.16+  | 
| [port](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#Destination)                        | 0.9.5         | 13.0–37.16+  | 
| [http.fault.abort.percentage](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPFaultInjection-Abort) | 0.9.5         | 13.0–37.16+  | 
| [http.fault.abort.httpStatus](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPFaultInjection-Abort) | 0.9.5          | 13.0–37.16+  | 
| [http.match.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)             | 0.9.5                 | 13.0–37.16+  | 
| [http.match.scheme](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 0.9.5                  | 13.0–37.16+  | 
| [http.match.method](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 0.9.5                  | 13.0–37.16+  | 
| [http.match.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)        | 0.9.5                  | 13.0–37.16+  | 
| [http.match.headers](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)          | 0.9.5                | 13.0–37.16+  | 
| [http.match.port](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPMatchRequest)            | 0.9.5                  |13.0–37.16+  | 
| [http.redirect.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRedirect)           | 0.9.5                     | 13.0–37.16+  | 
| [http.redirect.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRedirect)     | 0.9.5                   | 13.0–37.16+  | 
| [http.rewrite.uri](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRewrite)          | 0.9.5              |13.0–37.16+  | 
| [http.rewrite.authority](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#HTTPRewrite)       | 0.9.5         | 13.0–37.16+  | 
| [tcp.route.destination](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#TCPRoute)         | 0.9.5         | 13.0–37.16+  | 
| [tcp.route.weight](https://istio.io/docs/reference/config/networking/v1alpha3/virtual-service/#TCPRoute)         | 0.9.5         | 13.0–37.16+  | 
| [http.route.mirror](https://istio.io/docs/reference/config/networking/virtual-service/#HTTPRoute) | 0.9.5 | 13.0–47.22+  | 

**Note:** [http.route.mirrorPercentage](https://istio.io/docs/reference/config/networking/virtual-service/#HTTPRoute) will be supported in the next release.


## [Gateway](https://istio.io/latest/docs/reference/config/networking/gateway/)

Gateway specification describes a set of ports that should be exposed, the type of protocol to use, SNI configuration for the load balancer, and so on. The following table describes the gateway configuration settings supported by Citrix ADC with Istio.

| Field                                 | xDS-adaptor version | Citrix ADC Version |
|---------------------------------------|---------------|-----------------------------|
| [gateway.servers.port.number](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)          | 0.9.5         | 13.0–37.16+  | 
| [gateway.servers.port.protocol](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)        | 0.9.5         | 13.0–37.16+  |
| [gateway.servers.port.name](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Port)            | 0.9.5         | 13.0–37.16+  |
| [gateway.servers.hosts](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server)     | 0.9.5         |13.0–37.16+  | 
| [gateway.servers.tls.serverCertificate](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions) | 0.9.5         | 13.0–37.16+  | 
| [gateway.servers.tls.privateKey](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)        | 0.9.5         | 13.0–37.16+  | 
| [gateway.servers.tls.caCertificates](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)    | 0.9.5         |13.0–37.16+  | 
| [gateway.servers.tls.credentialName](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions)   | 0.9.5 |13.0–37.16+  | 
| [gateway.servers.tls.mode.SIMPLE](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions-TLSmode)       | 0.9.5  | 13.0–37.16+  | 
| [gateway.servers.tls.mode.MUTUAL](https://istio.io/docs/reference/config/networking/v1alpha3/gateway/#Server-TLSOptions-TLSmode)  | 0.9.5        |13.0–37.16+  | 

## [Service Entry](https://istio.io/latest/docs/reference/config/networking/service-entry/)

You can use the service entry to enable adding more entries into Istio’s internal service registry. Once you enable it, auto-discovered services in the mesh can access or route to these manually specified services.

| Field                               | xDS-adaptor version |  Citrix ADC Version |
|-------------------------------------|-----------------------|--------------------- |
| [serviceentry.hosts](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)                | 0.9.5         | 13.0–37.16+  | 
| [serviceentry.ports](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)               | 0.9.5         | 13.0–37.16+  | 
| [serviceentry.location.MESH_EXTERNAL](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Location) | 0.9.5         |13.0–37.16+  | 
| [serviceentry.location.MESH_INTERNAL](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Location) | 0.9.5         |13.0–37.16+  | 
| [serviceentry.resolution.DNS](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry-Resolution)       | 0.9.5         |13.0–37.16+  | 
| [serviceentry.exportTo](https://istio.io/docs/reference/config/networking/v1alpha3/service-entry/#ServiceEntry)  | 0.9.5 | 13.0–37.16+  | 
| [serviceentry-endpoint.weight](https://istio.io/docs/reference/config/networking/service-entry/#ServiceEntry-Location) | 0.9.5 |13.0–47.22+  | 

## [Authentication Policy](https://istio.io/latest/docs/reference/config/security/)

Using authentication policies you can specify authentication requirements for services receiving requests in an Istio service mesh. The following table describes the authentication policy settings supported by Citrix ADC with Istio.

| Field                          | xDS-adaptor version| Citrix ADC Version|
|--------------------------------|----------------------|---------------------| 
| [jwt](https://istio.io/docs/reference/config/security/jwt/#JWTRule)| 0.9.5 |13.0–37.16+  | 
| [jwt.issuer](https://istio.io/docs/reference/config/security/jwt/#JWTRule) | 0.9.5 | 13.0–37.16+  | 
| [jwt.audiences](https://istio.io/docs/reference/config/security/jwt/#JWTRule) | 0.9.5 |13.0–38.13+|
| [jwt.jwksUri](https://istio.io/docs/reference/config/security/jwt/#JWTRule) | 0.9.5 | 13.0–37.16+  |
| [mtls](https://istio.io/latest/docs/reference/config/security/peer_authentication/#PeerAuthentication) | 0.9.5  |13.0–37.16+  | 
| [mutualtls.mode.strict](https://istio.io/latest/docs/reference/config/security/peer_authentication/#PeerAuthentication-MutualTLS-Mode) | 0.9.5 |13.0–37.16+  |
