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
        -alias clientKeyPair1 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass clientKeyStore \
        -keystore clientKeyStore.jks

#generate client KeyStore
keytool -genkeypair \
        -alias clientKeyPair2 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass clientKeyStore \
        -keystore clientKeyStore.jks

#generate client KeyStore
keytool -genkeypair \
        -alias clientKeyPair3 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass clientKeyStore \
        -keystore clientKeyStore.jks

#Export Certificates

#store server public certificate
keytool -exportcert \
        -file certServer.der \
        -keystore serverKeyStore.jks \
        -storepass serverKeyStore \
        -alias serverKeyPair

#store server public certificate
keytool -exportcert \
        -file certClient1.der \
        -keystore clientKeyStore.jks \
        -storepass clientKeyStore \
        -alias clientKeyPair1

#store server public certificate
keytool -exportcert \
        -file certClient2.der \
        -keystore clientKeyStore.jks \
        -storepass clientKeyStore \
        -alias clientKeyPair2

#store server public certificate
keytool -exportcert \
        -file certClient3.der \
        -keystore clientKeyStore.jks \
        -storepass clientKeyStore \
        -alias clientKeyPair3

#store server certificate in clientLibrary keystore
#keytool -importcert \
#        -file cert.der \
#        -keystore clientKeyStore.jks \
#        -storepass clientKeyStore \
#        -noprompt \
#        -alias serverCert