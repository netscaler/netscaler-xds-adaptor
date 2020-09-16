# Helm Charts for Citrix ADC integration with Istio

This repository contains [helm](https://helm.sh) charts for installing Citrix ADC as Ingress/Egress Gateway and sidecar proxy in [Istio](https://istio.io)v1.6.4.


> Note: Charts may require access to kube-system namespace and/or cluster wide permissions for full functionality. Install/configure helm/tiller appropriately.

## Helm Installation
Please refer [Helm Installation Guide](https://github.com/citrix/citrix-helm-charts/blob/master/Helm_Installation_version_3.md)

###### Charts
[citrix-adc-istio-ingress-gateway](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-ingress-gateway) -Use this chart to deploy Citrix ADC as Ingress Gateway in Istio environment.

[citrix-cpx-istio-sidecar-injector](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-cpx-istio-sidecar-injector) -Use this chart to deploy resources responsible for injecting Citrix ADC CPX as sidecar in Istio Service Mesh.

[citrix-adc-istio-egress-gateway](https://github.com/citrix/citrix-helm-charts/tree/master/citrix-adc-istio-egress-gateway) -Use this chart to deploy Citrix ADC as Egress Gateway in Istio environment.


## Documentation
Chart's README describes the functionality and values.yaml shows the default values.
