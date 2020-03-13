# Release Notes

The Citrix `istio-adaptor` release notes describe new features, enhancements to existing features, fixed issues, and known issues available in the release. The latest version of `istio-adaptor` is available in the [Quay.io](https://quay.io/citrix/citrix-istio-adaptor) repository.

Release notes may include one or more of the following sections:

**What's new:** The new features and enhancements available in the current release.

**Fixed issues:** The issues that are fixed in the current release.

**Known issues:** The issues that exist in the current release and their workarounds, wherever applicable.

## Version 1.2.0-beta

### What’s new

#### Support for HTTP mirroring

Traffic mirroring provides a way to minimize the risk in bringing your application changes to production. Instead of routing production traffic to a newly deployed service, you can send a copy of the production traffic to a mirrored service. You can then observe the service that is receiving mirrored traffic for errors.

Citrix `istio-adaptor` now supports  [HTTP Traffic Mirroring](https://istio.io/docs/tasks/traffic-management/mirroring/). [NSNET-13891](https://issues.citrite.net/browse/NSNET-13891)

#### Support for Weighted Service Entry

A service entry describes the properties of a service (DNS name, VIPs, ports, protocols, endpoints). Using a weighted service entry, you can associate a load balancing weight with an endpoint. Endpoints with higher weights receive proportionally high traffic compared to endpoints with lower weights.

Citrix `istio-adaptor` now supports  [Weighted Service Entries](https://istio.io/docs/reference/config/networking/service-entry/#ServiceEntry-Endpoint). [NSNET-13514](https://issues.citrite.net/browse/NSNET-13514)

#### Support for Desired State API

Service group configuration on a Citrix ADC appliance requires frequent updates depending on the scale requirements or runtime changes to application servers. You can use desired state API and accept the intended member set for a service group in a single API and effectively update the configuration. Usage of desired state API improves the performance of updating servicegroup members significantly. 

Citrix `istio-adaptor` now supports  [Desired State APIs](https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/usecases/#update-service-group-with-desired-member-set-seamlessly-using-desired-state-api). [NSNET-12761](https://issues.citrite.net/browse/NSNET-12761)

#### Integration with Citrix Observability Exporter

Now, you can integrate a Citrix ADC deployed as an Istio sidecar with  [Citrix Observability Exporter](https://github.com/citrix/citrix-observability-exporter). Using Citrix Observability Exporter, you can export metrics and transactions from Citrix ADCs to desired endpoints such as Zipkin and Prometheus and analyze them to get valuable insights. [NSNET-11533](https://issues.citrite.net/browse/NSNET-11533)


## Version 1.1.0

### What's new

#### Support for Istio version 1.3.0

Citrix `istio-adaptor` now supports Istio release version 1.3.0.

#### Supported on Helm Hub

[Helm Hub](https://hub.helm.sh/) provides a means to easily find charts that are hosted outside the Helm project. Helm charts for Citrix `istio-adaptor` are now available on Helm Hub.

#### Support for HTTP service outlier detection

Outlier detection is a process to dynamically detect unusual host behavior and remove unhealthy hosts from the set of load balanced healthy hosts inside a cluster. Citrix `istio-adatptor` now supports [HTTP service outlier detection](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#OutlierDetection).

### Fixed issues

#### JWT Authentication

JSON Web Token (JWT) is an open standard for securely transmitting information between parties as JSON objects.

The following issues related to the JWT authentication are fixed in this release:

- JWTs sent in a custom request header or query parameter were not supported on Citrix ADCs. Now, it is supported on Citrix ADCs except Citrix ADC CPX. 
[NSAUTH-6176](https://issues.citrite.net/browse/NSNET-6176)

- Multiple audiences for JWT were not supported.
[NSAUTH-6178](https://issues.citrite.net/browse/NSNET-6178)
  
- JWT authentication was triggered for all paths in a request ignoring the list of paths specified using includedPaths and excludedPaths to bypass the authentication. [NSAUTH-6247](https://issues.citrite.net/browse/NSNET-6247)

#### Other Issues

The following issues related to Citrix ADC are fixed in this release:

- Citrix `istio-adaptor` requires premium license for Citrix ADC VPX or MPX and stops communication if the license type is not premium. [NSNET-12179](https://issues.citrite.net/browse/NSNET-12179)
  
- Citrix ADC VPX or MPX as Ingress Gateway: Uploading certificate and keys for Citrix ADC VPX or MPX fails if old key and certificate with the same name exists in Citrix ADC VPX or MPX. [NSNET-12371](https://issues.citrite.net/browse/NSNET-12371)

## Version 1.0.1-beta

### What's new

#### Support for Red Hat OpenShift Service Mesh

This release of Citrix `istio-adaptor` adds support for Red Hat OpenShift Service Mesh which is based on Istio release version 1.1.11.

The following Red Hat OpenShift cluster versions are supported:

- OpenShift cluster version 3.11
- OpenShift cluster versions 4.x onwards

#### Support for HTTP service outlier detection

Outlier detection is a process to dynamically detect unusual host behavior and remove unhealthy hosts from the set of load balanced healthy hosts inside a cluster. Citrix `istio-adaptor` now supports [HTTP service outlier detection](https://istio.io/docs/reference/config/networking/v1alpha3/destination-rule/#OutlierDetection).

### Fixed issues

#### JWT Authentication

JSON Web Token (JWT) is an open standard for securely transmitting information between parties as JSON objects.

The following issues related to the JWT authentication are fixed in this release:

- JWTs sent in a custom request header or query parameter were not supported on Citrix ADCs. Now, it is supported on Citrix ADCs except Citrix ADC CPX.
[NSAUTH-6176](https://issues.citrite.net/browse/NSNET-6176)

- Multiple audiences for JWT were not supported.
[NSAUTH-6178](https://issues.citrite.net/browse/NSNET-6178)
  
- JWT authentication was triggered for all paths in a request ignoring the list of paths specified using includedPaths and excludedPaths to bypass the authentication. [NSAUTH-6247](https://issues.citrite.net/browse/NSNET-6247)

#### Other Issues

The following issues related to Citrix ADC are fixed in this release:

- Citrix `istio-adaptor` requires premium license for Citrix ADC VPX or MPX and stops communication if the license type is not premium. [NSNET-12179](https://issues.citrite.net/browse/NSNET-12179)
  
- Citrix ADC VPX or MPX as Ingress Gateway: Uploading certificate and keys for Citrix ADC VPX or MPX fails if old key and certificate with the same name exists in Citrix ADC VPX or MPX. [NSNET-12371](https://issues.citrite.net/browse/NSNET-12371)



## Version 1.0.0

### What's New

This is the first release of Citrix `istio-adaptor`. `istio-adaptor` is Citrix's solution to configure Citrix ADC as an Ingress Gateway and/or sidecar proxy in Istio Service mesh. It acts as a client to gRPC based services in Istio control plane, listens to updates from the Pilot and configures Citrix ADC proxy using [NITRO](https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/) API calls.

Below are features which are supported in this release:

1. Service Discovery
2. Load Balancing
3. Secure Ingress for HTTP based services
4. Secure Ingress for TCP based services
5. Weighted Clusters
6. HTTP Rewrite and redirect
7. HTTP Fault Injection
8. End User Authentication using JWT
9. Transport Authentication using mTLS
10. Prometheus support for Ingress Gateway

The detailed list of fields supported on Citrix ADC as per the Istio CRDs (Destination Rule, Virtual Service, Policy, Gateway, Service Entry) can be found [here](features.md).


### Known Issues

1. Multiple audiences for JWT is not supported.
[NSAUTH-6178]

2. JWTs sent in a custom request header or query parameter are not supported in Citrix ADC.
[NSAUTH-6176]

3. JWT authentication happens for all paths. [`includedPaths`](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) and [`excludedPaths`](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) are not supported in Citrix ADC.
[NSAUTH-6247]

