# Citrix ADC CPX in Istio Helm Chart

This repository contains [helm](https://helm.sh) charts for installing Citrix ADC CPX as Ingress Gateway and sidecar proxy in [Istio](https://istio.io)v1.1.2.


> Note: Charts may require access to kube-system namespace and/or cluster wide permissions for full functionality. Install/configure helm/tiller appropriately.

## Helm Installation
Please refer [Helm Installation Guide](https://github.com/citrix/citrix-k8s-ingress-controller/blob/master/charts/Helm_Installation_Kubernetes.md)

## Stable Charts
The stable directory contains charts that are created and tested by Citrix.

###### Charts
[citrix-adc-istio-ingress-gateway](./stable/citrix-adc-istio-ingress-gateway) -Use this chart to deploy Citrix ADC as Ingress Gateway in Istio environment.

[citrix-cpx-istio-sidecar-injector](./stable/citrix-cpx-istio-sidecar-injector) -Use this chart to deploy resources responsible for injecting Citrix ADC CPX as sidecar in Istio Service Mesh.


## Documentation
Chart's README describes the functionality and values.yaml shows the default values.
