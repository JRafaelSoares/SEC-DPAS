#!/bin/bash

rm dpas-server/src/main/security/keys/*.jks
rm dpas-server/src/main/security/certificates/*.der
rm client-library/src/main/security/certificates/server/*.der
rm dpas-client/src/main/security/certificates/clients/*.der
rm dpas-client/src/main/security/keys/*.jks

#generate Server KeyStore
echo "Generating Keystore/PrivateKeys"

for server in {1..3}
do
echo "Generating Server Keystore/PrivateKeys ${server}"

keytool -genkeypair \
        -alias serverKeyPair$server \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass serverKeyStore \
        -keystore serverKeyStore.jks

keytool -exportcert \
        -file certServer$server.der \
        -keystore serverKeyStore.jks \
        -storepass serverKeyStore \
        -alias serverKeyPair$server

cp certServer$server.der dpas-server/src/main/security/certificates/
cp certServer$server.der dpas-client/src/main/security/certificates/server/
mv certServer$server.der client-library/src/main/security/certificates/server/
done

#Generate certificates

mv serverKeyStore.jks dpas-server/src/main/security/keys/

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
        -storepass clientKeyStore \
        -keystore clientKeyStore.jks

keytool -exportcert \
        -file certClient$client.der \
        -keystore clientKeyStore.jks \
        -storepass clientKeyStore \
        -alias clientKeyPair$client

mv certClient$client.der dpas-client/src/main/security/certificates/clients/
done

mv clientKeyStore.jks dpas-client/src/main/security/keys/
