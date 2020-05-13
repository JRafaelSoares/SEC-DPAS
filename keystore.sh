#!/bin/bash

rm dpas-server/src/main/security/keys/*.jks
rm dpas-server/src/main/security/certificates/*.der
rm client-library/src/main/security/certificates/server/*.der
rm dpas-client/src/main/security/certificates/clients/*.der
rm dpas-client/src/main/security/certificates/server/*.der
rm dpas-client/src/main/security/keys/*.jks

#generate Server KeyStore

let fault=1
let Nservers="$fault*3+1"

echo "Number of faults: $fault"
echo "Number of servers: $Nservers"

echo "Generating Keystore/PrivateKeys"
for (( server=0; server<$Nservers; server++ ))
do
echo "Generating Server Keystore/PrivateKeys ${server}"

keytool -genkeypair \
        -alias serverKeyPair$server \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass serverKeyStore$server \
        -keystore serverKeyStore$server.jks

keytool -exportcert \
        -file certServer$server.der \
        -keystore serverKeyStore$server.jks \
        -storepass serverKeyStore$server \
        -alias serverKeyPair$server

cp certServer$server.der dpas-server/src/main/security/certificates/
cp certServer$server.der dpas-client/src/main/security/certificates/server/
mv certServer$server.der client-library/src/main/security/certificates/server/
mv serverKeyStore$server.jks dpas-server/src/main/security/keys/
done

#Generate certificates

#generate client KeyStore

for client in {1..3}
do
echo "Generating Client Keystore/PrivateKey $client"

keytool -genkeypair \
        -alias clientKeyPair$client \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass clientKeyStore$client \
        -keystore clientKeyStore$client.jks

keytool -exportcert \
        -file certClient$client.der \
        -keystore clientKeyStore$client.jks \
        -storepass clientKeyStore$client \
        -alias clientKeyPair$client

mv certClient$client.der dpas-client/src/main/security/certificates/clients/
mv clientKeyStore$client.jks dpas-client/src/main/security/keys/
done


