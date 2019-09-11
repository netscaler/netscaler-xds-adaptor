# Release Notes

The Citrix `istio-adaptor` release notes describe new features, enhancements to existing features, fixed issues, and known issues available in the release. The latest version of `istio-adaptor` is available in the [Quay.io](https://quay.io/citrix/citrix-istio-adaptor) repository.

Release notes may include one or more of the following sections:

**What's new:** The new features and enhancements available in the current release.

**Fixed issues:** The issues that are fixed in the current release.

**Known issues:** The issues that exist in the current release and their workarounds, wherever applicable.


## Version 1.0.0-alpha

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

The detailed list of fields supported on Citrix ADC as per the Istio CRDs (Destination Rule, Virtual Service, Policy, Gateway, Service Entry) can be found [here](https://github.com/citrix/citrix-istio-adaptor/blob/master/docs/features.md/features.md).


### Known Issues

1. Multiple audiences for JWT is not supported.
[NSAUTH-6178]

2. JWTs sent in a custom request header or query parameter are not supported in Citrix ADC.
[NSAUTH-6176]

3. JWT authentication happens for all paths. [`includedPaths`](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) and [`excludedPaths`](https://istio.io/docs/reference/config/istio.authentication.v1alpha1/#Jwt-TriggerRule) are not supported in Citrix ADC.
[NSAUTH-6247]

