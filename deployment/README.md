
# Deploying Citrix ADC with Istio

This topic provides information on how to deploy Citrix ADC with Istio using Kubernetes YAML files. You can deploy Citrix ADC with Istio using Kubernetes YAML files or using Helm charts.
For information on deploying Citrix ADC with Istio using Helm charts, see [this](../charts/README.md)


# Table of Contents
1. [Prerequisites](#prerequisites)
2. [Deploy Citrix ADC as Ingress Gateway](#citrix-adc-ingress-gateway)
3. [Citrix ADC as Ingress Gateway: A Sample Deployment](#sample-deployment)
4. [Deploy Citrix ADC CPXs as sidecar proxies using YAML](#citrix-sidecar-injector)
5. [Clean Up of Citrix ADC Ingress Gateway](#cleanup-ingress)
6. [Clean Up of CPX sidecar injector resources](#cleanup-sidecar)

## <a name="prerequisites">A) Prerequisites</a>

-  Ensure that **Istio version 1.3.0** is installed
-  Ensure that your cluster has Kubernetes version 1.14.0 or later and the `admissionregistration.k8s.io/v1beta1` API is enabled

You can verify the API by using the following command:

        kubectl api-versions | grep admissionregistration.k8s.io/v1beta1

The following output indicates that the API is enabled:

        admissionregistration.k8s.io/v1beta1

- **Important Note:** _For deploying Citrix ADC VPX or MPX as ingress gateway, you should establish the connectivity between Citrix ADC VPX or MPX and cluster nodes. This connectivity can be established by configuring routes on Citrix ADC as mentioned [here](https://github.com/citrix/citrix-k8s-ingress-controller/blob/master/docs/network/staticrouting.md) or by deploying [Citrix Node Controller](https://github.com/citrix/citrix-k8s-node-controller).

## <a name="citrix-adc-ingress-gateway">B) Deploy Citrix ADC as Ingress Gateway</a>

Citrix ADC comes in various form factors ranging from Hardware based (MPX), Virtualized (VPX) and Containerized solution (CPX). Any form factor of the Citrix ADC can act as an Ingress Gateway to the Istio Service mesh.


## B.1) Deploy Citrix ADC CPX as an Ingress Gateway using YAML

You can deploy Citrix ADC CPX as an Ingress Gateway in Istio environment. In this deployment, `generate_yaml.sh` script is used to create a YAML file from the `cpx-ingressgateway.tmpl` template. This newly created YAML file is used to deploy Citrix ADC CPX in a Kubernetes namespace. Citrix ADC can act as an Ingress Gateway for standalone servicesor services deployed alongwith sidecar proxy (Envoy or Citrix CPX).

To deploy Citrix ADC CPX as an Ingress Gateway, perform the following steps.

1.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

2.  Change the permissions of the script to executable mode.

        chmod +x generate_yaml.sh

3.  Download the ``cpx-ingressgateway.tmpl`` template.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/cpx-ingressgateway.tmpl > cpx-ingressgateway.tmpl

4.  Create a YAML file from the template using the `generate_yaml.sh` script.

        ./generate_yaml.sh --inputfile cpx-ingressgateway.tmpl --outputfile cpx-ingressgateway.yaml 


    > **Note:**
    >To use particular images for Citrix ADC CPX and istio-adaptor, you can provide image details to the generate_yaml.sh script using `cpx-image-name` and `istio-adaptor-image-name` arguments. You can also provide licensing server IP address and port information using `license-server-ip` and `license-server-port` arguments. The following example shows how to specify the image details and licensing information while running the script to create the YAML file.


        ./generate_yaml.sh --inputfile cpx-ingressgateway.tmpl --outputfile cpx-ingressgateway.yaml --cpx-image-name quay.io/citrix/citrix-k8s-cpx-ingress --cpx-image-tag 13.0-41.28 --istio-adaptor-image-name quay.io/citrix/citrix-istio-adaptor --istio-adaptor-image-tag 1.1.0 --license-server-ip 10.102.101.101 --license-server-port 27000

5.  Deploy Citrix ADC CPX using the YAML file and specify the name space.

        kubectl create -f cpx-ingressgateway.yaml -n citrix-system


## B.2) Deploy Citrix ADC MPX or VPX as an Ingress Gateway using YAML

You can deploy Citrix ADC MPX or VPX as an Ingress Gateway in Istio environment. In this deployment, `generate_yaml.sh` script is used to create a YAML file from the `ingressgateway.tmpl` template. The newly created YAML file is used to deploy Citrix ADC MPX or VPX in a Kubernetes namespace.


To deploy Citrix ADC MPX or VPX as an Ingress Gateway, perform the following:

1.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

2.  Change the permissions of the script to executable mode.

        chmod +x generate_yaml.sh

3.  Download the `ingressgateway.tmpl` template.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/ingressgateway.tmpl > ingressgateway.tmpl

4.  Download the `secret.tmpl` YAML file template.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/secret.tmpl > secret.tmpl

5.  Generate the Kubernetes secret YAML file from the `secret.tmpl` template for VPX/MPX credentials.

         ./generate_yaml.sh --inputfile secret.tmpl --outputfile secret.yaml --username <username> --password <password>

6.  Create the Kubernetes secret object in the cluster.

        kubectl create -f secret.yaml -n citrix-system
7.  Create a YAML file from the `ingressgateway.tmpl` template using the `generate_yaml.sh` script.

        ./generate_yaml.sh --inputfile ingressgateway.tmpl --outputfile ingressgateway.yaml --netscaler-url https://<nsip>[:port] --vserver-ip <Virtual Server IPv4 Address> 

    >**Note:**
    >To use particular image for istio-adaptor, you can provide image details to the generate_yaml.sh script using the `istio-bdg-image-name` argument. The following example shows how to specify the image details while running the script to create the YAML file.

           ./generate_yaml.sh --inputfile ingressgateway.tmpl --outputfile ingressgateway.yaml --istio-adaptor-image-name quay.io/citrix/citrix-istio-adaptor --istio-adaptor-image-tag 1.1.0 --netscaler-url https://<nsip>[:port]

8.  Deploy Citrix ADC VPX or MPX using the `ingressgateway.yaml` file and specify the name space.

        kubectl create -f ingressgateway.yaml -n citrix-system


## <a name="sample-deployment">C) Citrix ADC as Ingress Gateway: A Sample Deployment</a>

A sample deployment of Citrix ADC as an Ingress gateway for the Bookinfo application is provided [here]( https://github.com/citrix/citrix-istio-adaptor/blob/master/examples/citrix-adc-in-istio).


## <a name="citrix-sidecar-injector">D) Deploy Citrix ADC CPXs as sidecar proxies using YAML</a>

Citrix ADC CPX can act as a sidecar proxy to the application container in Istio service mesh. You can either inject Citrix ADC CPX automatically or manually in the application pod. However, the injection process requires certain Kubernetes resources. For manual injection, Kubernetes ConfigMap resource is required. Automatic injection requires a Kubernetes mutating webhook admission controller, a service, and a deployment.

In Istio servicemesh, the namespace must be labelled before applying the deployment yaml for [automatic sidecar injection](https://istio.io/docs/setup/kubernetes/additional-setup/sidecar-injection/#automatic-sidecar-injection). Once the namespace is labelled, sidecars (envoy or CPX) will be injected while creating pods.
- For Citrix ADC CPX, namespace must be labelled `cpx-injection=enabled`
- For Envoy, namespace must be labelled `istio-injection=enabled`

__Note: If a namespace is labelled with both `istio-injection` and `cpx-injection`, Envoy injection takes a priority! Citrix CPX won't be injected on top of the already injected Envoy sidecar. For using Citrix ADC as sidecar, ensure that `istio-injection` label is removed from the namespace.__

To deploy Citrix ADC CPX as a sidecar using Helm charts, see [Deploy Citrix ADC CPX as a sidecar using Helm charts](../charts/stable/citrix-cpx-istio-sidecar-injector/README.md).

## D.1) Deploy Citrix ADC CPX as a sidecar using automatic injection

#### Prerequisites

You must create the resources required for automatic sidecar injection by performing the following steps:

1.  Download the `webhook-create-signed-cert.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/webhook-create-signed-cert.sh > webhook-create-signed-cert.sh

2.  Change the permissions of the script to executable mode.

        chmod +x webhook-create-signed-cert.sh
3.  Create a signed certificate, key pair and store it in a Kubernetes secret.

        ./webhook-create-signed-cert.sh \
        --service cpx-sidecar-injector \
        --secret cpx-sidecar-injector-certs \
        --namespace citrix-system

4.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

5.  Change the permissions of the script to executable mode.

        chmod +x generate_yaml.sh

6.  Download the `cpx-sidecar-injection-all-in-one.tmpl`  file template.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/cpx-sidecar-injection-all-in-one.tmpl > cpx-sidecar-injection-all-in-one.tmpl

7.  Generate the `cpx-sidecar-injection-all-in-one` YAML file from the `cpx-sidecar-injection-all-in-one.tmpl` template.

        ./generate_yaml.sh --inputfile cpx-sidecar-injection-all-in-one.tmpl --outputfile cpx-sidecar-injection-all-in-one.yaml --namespace citrix-system

8.  Deploy all sidecar resources using the `cpx-sidecar-injection-all-in-one` YAML file.

        kubectl create -f cpx-sidecar-injection-all-in-one.yaml -n citrix-system

Once you create the required resources, perform the following steps
to deploy CPX as a sidecar using automatic injection:

1.  Verify that the sidecar inject webhook is running.

        kubectl get pods -n citrix-system
        NAME                                    READY   STATUS    RESTARTS   AGE
        cpx-sidecar-injector-77b87db747-v96bw   1/1     Running   0         153m

2.  Label the namespace where you are deploying Citrix ADC CPX as sidecar with `cpx-injection=enabled` and verify the status.

        kubectl label namespace default cpx-injection=enabled

        kubectl get namespace --show-labels

        NAME            STATUS   AGE      Label
        
        citrix-system   Active   24d   name=citrix-system
        default         Active   48d   cpx-injection enabled

3.  Deploy a sample application in Kubernetes cluster in default namespace. In this example, [sleep](https://raw.githubusercontent.com/istio/istio/release-1.1/samples/sleep/sleep.yaml) application is used. Automatic injection of Citrix ADC CPX happens at the time of creating pod.

        kubectl apply -f sleep.yaml

4.  Verify the sidecar injection using the following command.

        kubectl get pods
        NAME                     READY   STATUS    RESTARTS   AGE
        sleep-7549f66447-c6jc8   3/3     Running   0          146m

## D.2) Deploy Citrix ADC CPX as sidecar using manual injection

#### Prerequisites

You must create a ConfigMap resource by performing the following steps:

1.  Create a Kubernetes namespace.

        kubectl create namespace citrix-system

2.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

3.  Change the permissions of the script to executable mode.

        chmod +x generate_yaml.sh

4.  Download the YAML file template for ConfigMap.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/cpx-sidecar-injector-configmap.tmpl > cpx-sidecar-injector-configmap.tmpl

5.  Generate the `cpx-sidecar-injector-configmap.yaml` file from the `cpx-sidecar-injector-configmap.tmpl` template.

        ./generate_yaml.sh --inputfile cpx-sidecar-injector-configmap.tmpl --outputfile cpx-sidecar-injector-configmap.yaml

6.  Create ConfigMap in the desired Kubernetes name space.

        kubectl apply -f cpx-sidecar-injector-configmap.yaml -n citrix-system

Once you create the ConfigMap, perform the following steps to manually inject Citrix ADC CPX as a sidecar with an application.

7.  Inject Citrix ADC CPX as a sidecar with the desired application using the `istioctl kube-inject` command. In this example, [sleep](https://raw.githubusercontent.com/istio/istio/release-1.1/samples/sleep/sleep.yaml) application is used.

        istioctl kube-inject --istioNamespace citrix-system --injectConfigMapName cpx-istio-sidecar-injector -f sleep.yaml -o sleep-cpx.yaml

8.  Deploy the application using the injected YAML file.

        kubectl apply -f sleep-cpx.yaml

## D.3) Limitations

Citrix ADC CPX occupies certain ports for internal usage. This makes application service running on one of these restricted ports incompatible with the Citrix ADC CPX.
The list of ports is mentioned below. Citrix is working on delisting some of the major ports from the given list, and same shall be available in future releases.

#### Restricted Ports

| Sr No |Port Number|
|-------|-----------|
| 1 | 80 |
| 2 | 3010 |
| 3 | 5555 |
| 4 | 8080 |


## <a name="cleanup-ingress">E) Clean Up of Citrix ADC Ingress Gateway</a>

## E.1) Cleaning up Citrix ADC CPX Ingress Gateway

To delete a Citrix ADC CPX which is deployed as an Ingress Gateway, perform the following steps.

1.  Use the `kubectl delete` command and specify the `cpx-ingressgateway.yaml` file generated in [Deploy Citrix ADC CPX as an Ingress Gateway using YAML](#deploy-citrix-adc-cpx-as-an-ingress-gateway-using-yaml).

        kubectl delete -f cpx-ingressgateway.yaml -n citrix-system

1.  Delete the Kubernetes namespace.

        kubectl delete namespace citrix-system

## E.2) Cleaning up Citrix ADC MPX or VPX as an Ingress Gateway

To delete a Citrix ADC MPX or VPX which is deployed as an Ingress Gateway, perform the following steps.

1.  Use the `kubectl delete` command and specify the `ingressgateway.yaml` file generated in [Deploy Citrix ADC MPX or VPX as an Ingress Gateway using YAML](#deploy-citrix-adc-mpx-or-vpx-as-an-ingress-gateway-using-yaml).

        kubectl delete -f ingressgateway.yaml -n citrix-system

2.  Delete the Kubernetes namespace.

        kubectl delete namespace citrix-system


## <a name="cleanup-sidecar">F) Clean Up of CPX sidecar injector resources </a>

To delete Citrix ADC CPX resources created for automatic injection, perform the following step.

1.  Use the `kubectl delete` command and specify the `cpx-sidecar-injection-all-in-one.yaml` file generated in [Deploy Citrix ADC CPX as a sidecar using automatic injection](#deploy-citrix-adc-cpx-as-a-sidecar-using-automatic-injection).

        kubectl delete -f cpx-sidecar-injection-all-in-one.yaml -n citrix-system
