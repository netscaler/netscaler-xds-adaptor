# Release Notes

The Citrix `xds-adaptor` release notes describe new features, enhancements to existing features, fixed issues, and known issues available in the release. The latest version of `xds-adaptor` is available in the [Quay.io](https://quay.io/citrix/citrix-xds-adaptor) repository.

Release notes may include one or more of the following sections:

**What's new:** The new features and enhancements available in the current release.

**Fixed issues:** The issues that are fixed in the current release.

**Known issues:** The issues that exist in the current release and their workarounds, wherever applicable.

## Version 0.9.5-beta

### What’s New

#### Introduction of the Citrix xDS-adaptor for service mesh

Citrix `xDS-adaptor` is a non-Envoy xDS client that converts [xDS API](https://github.com/envoyproxy/data-plane-api) (data plane API) into an equivalent Citrix ADC configuration. The `xDS-adaptor` is a container that connects to an xDS API server such as Istiod, listens to updates, and configures a Citrix ADC. It enables Citrix ADC to integrate with different service meshes such as Istio.

The `xDS-adaptor` enables organizations to deploy their existing ADC appliances into Kubernetes environments and supports different versions of the xDS API. This release of `xDS-adaptor` is compatible with go-control-plane v0.9.5.

#### Support for Citrix ADC CPX as an Egress Gateway in Istio

An Egress Gateway controls egress traffic and defines the traffic exit point in the Istio service mesh. Citrix ADC CPX as an Egress Gateway performs load balancing and monitoring at the edge of the service mesh and provides routing rules to exit the mesh. You can deploy Citrix ADC CPX as an Egress Gateway in Istio using the [Helm](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-egress-gateway) charts.

#### Support for Istio 1.6.4

The `xDS-adaptor` supports Istio 1.6.4 and helps in integrating Citrix ADC with Istio and other service meshes.

#### Support for certificate generation for services

Citrix ADC as a sidecar-proxy, an Ingress Gateway, or an Egress Gateway requires a TLS certificate-key pair for establishing secure communication channel with back end applications. Earlier, Istio Citadel is used to issue certificates and bundle them into a Kubernetes secret. Certificate was loaded in the application pod by performing the volume mount of the secret. Now, `xDS-adaptor` can generate its own certificate and get it signed by the Istio Citadel (Istiod). This process eliminates the need of the secret and the associated risks.

### Known Issues

By disabling TLS, you cannot make service-to-service communication as insecure. Only, a secure connection is possible between services.
