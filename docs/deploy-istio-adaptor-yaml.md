# Deploying Citrix ADC with Istio

Citrix ADC comes in various form factors ranging from hardware based (MPX), virtualized (VPX) and containerized solution (CPX). Any form factor of the Citrix ADC can act as an Ingress Gateway to the Istio service mesh. Citrix ADC CPXs can act as sidecar proxies to the application container in Istio service mesh.

This topic provides information on how to deploy Citrix ADC with Istio using Kubernetes YAML files. You can deploy Citrix ADC with Istio using Kubernetes YAML files or using Helm charts.
For information on deploying Citrix ADC with Istio using Helm charts, see [using Helm](deploy-istio-adaptor-helm-chart.md).

## Prerequisites

- Ensure that Istio version 1.3.0 is installed
- Ensure that your cluster has Kubernetes version 1.14.0 or later and the `admissionregistration.k8s.io/v1beta1` API is enabled

You can verify the API by using the following command:

       kubectl api-versions | grep admissionregistration.k8s.io/v1beta1

The following output indicates that the API is enabled:
       
       admissionregistration.k8s.io/v1beta1

**Note:** For deploying Citrix ADC VPX or MPX as an Ingress Gateway, you should establish the connectivity between Citrix ADC VPX or MPX and cluster nodes. This connectivity can be established by configuring routes on Citrix ADC as mentioned [here](https://github.com/citrix/citrix-k8s-ingress-controller/blob/master/docs/network/staticrouting.md) or by deploying [Citrix Node Controller](https://github.com/citrix/citrix-k8s-node-controller).

## Deploy Citrix ADC CPX as an Ingress Gateway using YAML

You can deploy Citrix ADC CPX as an Ingress Gateway in the Istio environment. In this deployment, `generate_yaml.sh` script is used to create a YAML file from the `cpx-ingressgateway.tmpl` template. This newly created YAML file is used to deploy Citrix ADC CPX in a Kubernetes namespace. Citrix ADC can act as an Ingress Gateway for standalone services or services deployed along with sidecar proxy (Envoy or Citrix CPX).
To deploy Citrix ADC CPX as an Ingress Gateway, perform the following steps.

1.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

2.  Change the permissions of the script to executable mode.

        chmod +x generate_yaml.sh

3.  Download the ``cpx-ingressgateway.tmpl`` template.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/cpx-ingressgateway.tmpl > cpx-ingressgateway.tmpl

4.  Create a YAML file from the template using the generate_yaml.sh script.
   
        ./generate_yaml.sh --inputfile cpx-ingressgateway.tmpl --outputfile cpx-ingressgateway.yaml
       > **Note:**
       >To use particular images for Citrix ADC CPX and istio-adaptor, you can provide image details to the `generate_yaml.sh` script using cpx-image-name and istio-adaptor-image-name arguments. You can also provide licensing server IP address and port information using license-server-ip and license-server-port arguments.
  
       The following example shows how to specify the image details and licensing information while running the script to create the YAML file.


        ./generate_yaml.sh --inputfile cpx-ingressgateway.tmpl --outputfile cpx-ingressgateway.yaml --cpx-image-name quay.io/citrix/citrix-k8s-cpx-ingress --cpx-image-tag 13.0-41.28 --istio-adaptor-image-name quay.io/citrix/citrix-istio-adaptor --istio-adaptor-image-tag 1.1.0 --license-server-ip 10.102.101.101 --license-server-port 27000

5.  Deploy Citrix ADC CPX using the YAML file and specify the name space.
       
        kubectl create -f cpx-ingressgateway.yaml -n citrix-system

## Deploy Citrix ADC MPX or VPX as an Ingress Gateway using YAML

You can deploy Citrix ADC MPX or VPX as an Ingress Gateway in Istio environment. In this deployment, `generate_yaml.sh` script is used to create a YAML file from the `ingressgateway.tmpl` template. The newly created YAML file is used to deploy Citrix ADC MPX or VPX in a Kubernetes namespace.
To deploy Citrix ADC MPX or VPX as an Ingress Gateway, perform the following:

1.  Download the `generate_yaml.sh` script.
   
        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh
1.  Change permissions of the script to executable mode.
   
        chmod +x generate_yaml.sh
1.  Download the `ingressgateway.tmpl` template.
   
        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/ingressgateway.tmpl > ingressgateway.tmpl
1.  Download the `secret.tmpl` YAML file template.
   
        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/secret.tmpl > secret.tmpl
1.  Generate the Kubernetes secret YAML file from the `secret.tmpl`template for Citrix ADC VPX or MPX credentials.

        ./generate_yaml.sh --inputfile secret.tmpl --outputfile secret.yaml --username <username> --password <password>
1.  Create the Kubernetes secret object in the cluster.

        kubectl create -f secret.yaml -n citrix-system
1.  Create a YAML file from the `ingressgateway.tmpl` template using the generate_yaml.sh script.
   
        ./generate_yaml.sh --inputfile ingressgateway.tmpl --outputfile ingressgateway.yaml --netscaler-url https://<nsip>[:port] --vserver-ip <Virtual Server IPv4 Address>
    >**Note:**
    >To use a specific image for `istio-adaptor`, you can provide image details to the `generate_yaml.sh` script using the `istio-bdg-image-name` argument.
   
    The following example shows how to specify the image details while running the script to create the YAML file.

          ./generate_yaml.sh --inputfile ingressgateway.tmpl --outputfile ingressgateway.yaml --istio-adaptor-image-name quay.io/citrix/citrix-istio-adaptor --istio-adaptor-image-tag 1.1.0 --netscaler-url https://<nsip>[:port]
1. Deploy Citrix ADC VPX or MPX using the `ingressgateway.yaml` file and specify the name space.
   
       kubectl create -f ingressgateway.yaml -n citrix-system

## Citrix ADC as Ingress Gateway: A sample deployment

A sample deployment of Citrix ADC as an Ingress gateway for the Bookinfo application is provided in [examples]( https://github.com/citrix/citrix-istio-adaptor/blob/master/examples/citrix-adc-in-istio).

## Deploy Citrix ADC CPXs as sidecar proxies using YAML

Citrix ADC CPX can act as a sidecar proxy to the application container in Istio service mesh. You can either inject Citrix ADC CPX automatically or manually in the application pod. However, the injection process requires certain Kubernetes resources. For manual injection, Kubernetes ConfigMap resource is required. Automatic injection requires a Kubernetes mutating webhook admission controller, a service, and a deployment.
In Istio servicemesh, the namespace must be labeled before applying the deployment yaml for [automatic sidecar injection](https://istio.io/docs/setup/kubernetes/additional-setup/sidecar-injection/#automatic-sidecar-injection). Once the namespace is labeled, sidecars (Envoy or Citrix ADC CPX) are injected while creating pods.

- For Citrix ADC CPX, namespace must be labeled as `cpx-injection=enabled`
- For Envoy, namespace must be labeled as `istio-injection=enabled`

>**Note:** If a namespace is labeled with both `istio-injection` and `cpx-injection`, Envoy injection takes priority. You cannot inject Citrix ADC CPX on top of the already injected Envoy sidecar. For using Citrix ADC CPX as sidecar, ensure that the `istio-injection` label is removed from the namespace.

To deploy Citrix ADC CPX as a sidecar using Helm charts, see [Deploy Citrix ADC CPX as a sidecar using Helm charts](../charts/stable/citrix-cpx-istio-sidecar-injector/README.md).

### Deploy Citrix ADC CPX as a sidecar using automatic injection

**Prerequisites**

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

Once you create the required resources, perform the following steps to deploy Citrix ADC CPX as a sidecar using automatic injection:

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

### Deploy Citrix ADC CPX as sidecar using manual injection

**Prerequisites**

You must create a ConfigMap resource by performing the following steps:

1.  Create a Kubernetes namespace.

        kubectl create namespace citrix-system

2.  Download the `generate_yaml.sh` script.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/generate_yaml.sh > generate_yaml.sh

3.  Change permissions of the script to executable mode.

        chmod +x generate_yaml.sh

4.  Download the YAML file template for ConfigMap.

        curl -L https://raw.githubusercontent.com/citrix/citrix-istio-adaptor/master/deployment/cpx-sidecar-injector-configmap.tmpl > cpx-sidecar-injector-configmap.tmpl

5.  Generate the `cpx-sidecar-injector-configmap.yaml` file from the `cpx-sidecar-injector-configmap.tmpl` template.

        ./generate_yaml.sh --inputfile cpx-sidecar-injector-configmap.tmpl --outputfile cpx-sidecar-injector-configmap.yaml

6.  Create a ConfigMap in the desired Kubernetes name space.

        kubectl apply -f cpx-sidecar-injector-configmap.yaml -n citrix-system

Once you create the ConfigMap, perform the following steps to manually inject Citrix ADC CPX as a sidecar with an application.

1.  Inject Citrix ADC CPX as a sidecar with the desired application using the `istioctl kube-inject` command. In this example, [sleep](https://raw.githubusercontent.com/istio/istio/release-1.1/samples/sleep/sleep.yaml) application is used.

        istioctl kube-inject --istioNamespace citrix-system --injectConfigMapName cpx-istio-sidecar-injector -f sleep.yaml -o sleep-cpx.yaml

8.  Deploy the application using the injected YAML file.

        kubectl apply -f sleep-cpx.yaml

### Limitations

Citrix ADC CPX occupies certain ports for internal usage. This makes application service running on one of these restricted ports incompatible with the Citrix ADC CPX.
The list of ports is mentioned as follows.

**Restricted Ports**

| Sr No |Port Number|
|-------|-----------|
| 1 | 80 |
| 2 | 3010 |
| 3 | 5555 |
| 4 | 8080 |

### Cleaning up Citrix ADC CPX Ingress Gateway

To delete a Citrix ADC CPX which is deployed as an Ingress Gateway, perform the following steps.

1.  Use the `kubectl delete` command and specify the `cpx-ingressgateway.yaml` file generated in [Deploy Citrix ADC CPX as an Ingress Gateway using YAML](#deploy-citrix-adc-cpx-as-an-ingress-gateway-using-yaml).

        kubectl delete -f cpx-ingressgateway.yaml -n citrix-system

2.  Delete the Kubernetes namespace.

        kubectl delete namespace citrix-system

### Cleaning up Citrix ADC MPX or VPX as an Ingress Gateway

To delete a Citrix ADC MPX or VPX which is deployed as an Ingress Gateway, perform the following steps.

1.  Use the `kubectl delete` command and specify the `ingressgateway.yaml` file generated in [Deploy Citrix ADC MPX or VPX as an Ingress Gateway using YAML](#deploy-citrix-adc-mpx-or-vpx-as-an-ingress-gateway-using-yaml).

        kubectl delete -f ingressgateway.yaml -n citrix-system

2.  Delete the Kubernetes namespace.

        kubectl delete namespace citrix-system

### Cleaning up Citrix ADC CPX sidecar injector resources

To delete Citrix ADC CPX resources created for automatic injection, perform the following step.

1.  Use the `kubectl delete` command and specify the `cpx-sidecar-injection-all-in-one.yaml` file generated in [Deploy Citrix ADC CPX as a sidecar using automatic injection](#deploy-citrix-adc-cpx-as-a-sidecar-using-automatic-injection).

        kubectl delete -f cpx-sidecar-injection-all-in-one.yaml -n citrix-system