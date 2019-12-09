openssl genrsa -out tests/certs/certrotation/rootCA.key 4096
openssl req -new -key tests/certs/certrotation/rootCA.key -out tests/certs/certrotation/rootCA.csr -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=rotationroot.com"
openssl x509 -req -in tests/certs/certrotation/rootCA.csr -sha256 -days 365 -extensions v3_ca -signkey tests/certs/certrotation/rootCA.key -CAcreateserial -out tests/certs/certrotation/rootCA.crt

openssl genrsa -out tests/certs/certrotation/app1.1000.rotationroot.com.key 2048
openssl req -new -sha256 -key tests/certs/certrotation/app1.1000.rotationroot.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=app1.rotationroot.com" -out tests/certs/certrotation/app1.1000.rotationroot.com.csr
openssl x509 -req -in tests/certs/certrotation/app1.1000.rotationroot.com.csr -CA tests/certs/certrotation/rootCA.crt -CAkey tests/certs/certrotation/rootCA.key -CAcreateserial -out tests/certs/certrotation/app1.1000.rotationroot.com.crt -days 1001 -sha256
openssl genrsa -out tests/certs/certrotation/app1.500.rotationroot.com.key 2048
openssl req -new -sha256 -key tests/certs/certrotation/app1.500.rotationroot.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=app1.rotationroot.com" -out tests/certs/certrotation/app1.500.rotationroot.com.csr
openssl x509 -req -in tests/certs/certrotation/app1.500.rotationroot.com.csr -CA tests/certs/certrotation/rootCA.crt -CAkey tests/certs/certrotation/rootCA.key -CAcreateserial -out tests/certs/certrotation/app1.500.rotationroot.com.crt -days 501 -sha256

rm -f tests/certs/certrotation/app1.1000.rotationroot.com.csr tests/certs/certrotation/rootCA.srl tests/certs/certrotation/rootCA.key tests/certs/certrotation/rootCA.csr tests/certs/certrotation/app1.500.rotationroot.com.csr

openssl genrsa -out tests/certs/certssvc1/rootCA.key 4096
openssl req -new -key tests/certs/certssvc1/rootCA.key -out tests/certs/certssvc1/rootCA.csr -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=citrixrootdummy1.com"
openssl x509 -req -in tests/certs/certssvc1/rootCA.csr -sha256 -days 365 -extensions v3_ca -signkey tests/certs/certssvc1/rootCA.key -CAcreateserial -out tests/certs/certssvc1/rootCA.crt

openssl genrsa -out tests/certs/certssvc1/svc1.citrixrootdummy1.com.key 2048
openssl req -new -sha256 -key tests/certs/certssvc1/svc1.citrixrootdummy1.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=svc1.citrixrootdummy1.com" -out tests/certs/certssvc1/svc1.citrixrootdummy1.com.csr
openssl x509 -req -in tests/certs/certssvc1/svc1.citrixrootdummy1.com.csr -CA tests/certs/certssvc1/rootCA.crt -CAkey tests/certs/certssvc1/rootCA.key -CAcreateserial -out tests/certs/certssvc1/svc1.citrixrootdummy1.com.crt -sha256

rm -f tests/certs/certssvc1/svc1.citrixrootdummy1.com.csr tests/certs/certssvc1/rootCA.srl tests/certs/certssvc1/rootCA.key tests/certs/certssvc1/rootCA.csr

openssl genrsa -out tests/certs/certssvc2/rootCA.key 4096
openssl req -new -key tests/certs/certssvc2/rootCA.key -out tests/certs/certssvc2/rootCA.csr -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=citrixrootdummy2.com"
openssl x509 -req -in tests/certs/certssvc2/rootCA.csr -sha256 -days 365 -extensions v3_ca -signkey tests/certs/certssvc2/rootCA.key -CAcreateserial -out tests/certs/certssvc2/rootCA.crt

openssl genrsa -out tests/certs/certssvc2/svc2.citrixrootdummy2.com.key 2048
openssl req -new -sha256 -key tests/certs/certssvc2/svc2.citrixrootdummy2.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=svc2.citrixrootdummy2.com" -out tests/certs/certssvc2/svc2.citrixrootdummy2.com.csr
openssl x509 -req -in tests/certs/certssvc2/svc2.citrixrootdummy2.com.csr -CA tests/certs/certssvc2/rootCA.crt -CAkey tests/certs/certssvc2/rootCA.key -CAcreateserial -out tests/certs/certssvc2/svc2.citrixrootdummy2.com.crt -sha256

rm -f tests/certs/certssvc2/svc2.citrixrootdummy2.com.csr tests/certs/certssvc2/rootCA.srl tests/certs/certssvc2/rootCA.key tests/certs/certssvc2/rootCA.csr

openssl genrsa -out tests/certs/certssvca/rootCA1.key 4096
openssl req -new -key tests/certs/certssvca/rootCA1.key -out tests/certs/certssvca/rootCA1.csr -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=dummyrootcitrix1.com"
openssl x509 -req -in tests/certs/certssvca/rootCA1.csr -sha256 -days 365 -extensions v3_ca -signkey tests/certs/certssvca/rootCA1.key -CAcreateserial -out tests/certs/certssvca/rootCA1.crt

openssl genrsa -out tests/certs/certssvca/svca.dummyrootcitrix1.com.key 2048
openssl req -new -sha256 -key tests/certs/certssvca/svca.dummyrootcitrix1.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=svca.dummyrootcitrix1.com" -out tests/certs/certssvca/svca.dummyrootcitrix1.com.csr
openssl x509 -req -in tests/certs/certssvca/svca.dummyrootcitrix1.com.csr -CA tests/certs/certssvca/rootCA1.crt -CAkey tests/certs/certssvca/rootCA1.key -CAcreateserial -out tests/certs/certssvca/svca.dummyrootcitrix1.com.crt -sha256

rm -f tests/certs/certssvca/svca.dummyrootcitrix1.com.csr tests/certs/certssvca/rootCA1.srl tests/certs/certssvca/rootCA1.key tests/certs/certssvca/rootCA1.csr

openssl genrsa -out tests/certs/certssvcb/rootCA2.key 4096
openssl req -new -key tests/certs/certssvcb/rootCA2.key -out tests/certs/certssvcb/rootCA2.csr -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=dummyrootcitrix2.com"
openssl x509 -req -in tests/certs/certssvcb/rootCA2.csr -sha256 -days 365 -extensions v3_ca -signkey tests/certs/certssvcb/rootCA2.key -CAcreateserial -out tests/certs/certssvcb/rootCA2.crt

openssl genrsa -out tests/certs/certssvcb/svcb.dummyrootcitrix2.com.key 2048
openssl req -new -sha256 -key tests/certs/certssvcb/svcb.dummyrootcitrix2.com.key -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=svcb.dummyrootcitrix2.com" -out tests/certs/certssvcb/svcb.dummyrootcitrix2.com.csr
openssl x509 -req -in tests/certs/certssvcb/svcb.dummyrootcitrix2.com.csr -CA tests/certs/certssvcb/rootCA2.crt -CAkey tests/certs/certssvcb/rootCA2.key -CAcreateserial -out tests/certs/certssvcb/svcb.dummyrootcitrix2.com.crt -sha256

rm -f tests/certs/certssvcb/svcb.dummyrootcitrix2.com.csr tests/certs/certssvcb/rootCA2.srl tests/certs/certssvcb/rootCA2.key tests/certs/certssvcb/rootCA2.csr

kubectl get secrets -n istio-system istio.istio-pilot-service-account -o jsonpath="{.data.root-cert\.pem}"  > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/client-root-cert.pem
kubectl get secrets -n istio-system istio.istio-pilot-service-account -o jsonpath="{.data.cert-chain\.pem}" > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/client-cert.pem
kubectl get secrets -n istio-system istio.istio-pilot-service-account -o jsonpath="{.data.key\.pem}" > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/client-key.pem
kubectl get secrets -n default istio.default -o jsonpath="{.data.root-cert\.pem}"  > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/root-cert.pem
kubectl get secrets -n default istio.default -o jsonpath="{.data.cert-chain\.pem}" > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/cert-chain.pem
kubectl get secrets -n default istio.default -o jsonpath="{.data.key\.pem}" > deco && base64 deco --decode > tests/certs/tls_conn_mgmt_certs/key.pem
rm -f deco

