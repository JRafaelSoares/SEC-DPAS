#!/bin/bash

rm *.jks 

#generate Server KeyStore
keytool -genkeypair \
        -alias serverKeyPair \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass serverKeyStore \
        -keystore serverKeyStore.jks

#generate client KeyStore
keytool -genkeypair \
        -alias clientKeyPair \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass clientKeyStore \
        -keystore clientKeyStore.jks

#store server public certificate
keytool -exportcert \
        -file cert.der \
        -keystore serverKeyStore.jks \
        -storepass serverKeyStore \
        -alias serverKeyPair

#store server certificate in clientLibrary keystore
#keytool -importcert \
#        -file cert.der \
#        -keystore clientKeyStore.jks \
#        -storepass clientKeyStore \
#        -noprompt \
#        -alias serverCert