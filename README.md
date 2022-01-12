# czechidm-sign

This module provide signing end crypting functionality via JWS and JWE.  
You can use only JWE or JWS depends on your use case. If you need both, there are methods in service which will do it for you.  
This module providing only backend services at the moment. 

Signing and crypting
* Plain text is signed by private part of RSA key(JWS). RS256 algorithm is used
* This signed and coded string is then encrypted(JWE)
* JWE using RSA-OAEP for key and A128CBC_HS256 for content. Crypting is done via public part of RSA key

Velidating and decrypting
* Private part of RSA key is used for decrypt
* Public part of RSA key is used for validating signature
* If signing is OK, plain text is returned

You can use diffrent key pair for signing and for encrypting. In fact this is recommended.
For inspiration how to call methods from service, you can look into [test class](https://github.com/bcvsolutions/czechidm-sign/blob/develop/Realization/backend/idm-sign/src/test/java/eu/bcvsolutions/idm/sign/service/impl/DefaultSignSignatureServiceTest.java).
### IdM configuration properties
idm.sec.signkeystoreLocation=path/to/keystore.jks  
idm.sec.signkeystorePassword=password to keystore

### Preparing keystore
`openssl genrsa -out fakecert.key`  
`openssl req -new -key fakecert.key -out fakecert.csr -subj "/C=CZ/ST=Czech Republic/L=Prague/O=BCV/CN=CzechIdM placeholder cert" `  
`openssl x509 -req -in fakecert.csr -signkey fakecert.key -days 1 -sha256 -out fakecert.crt`  
`keytool -importcert -file fakecert.crt -alias placeholder-cert -keystore truststore.jks`  
`    Enter keystore password:  ENTER SOME PASSWORD HERE AND REMEMBER IT FOR LATER`  
`    Re-enter new password:`  
`    ...`  
`    Trust this certificate? [no]:  yes`  
`    Certificate was added to keystore`  
`rm fakecert.key fakecert.csr fakecert.crt`  
`chmod 644 truststore.jks`  

### Generating Key
`openssl req -nodes -newkey rsa:3072 -x509 -keyout key.pem -out cert.pem -days 365`  
`openssl pkcs12 -export -in cert.pem -inkey key.pem -out certificate.p12 -name "signingkey"` Password must be same as for trustore  
`keytool -importkeystore -srckeystore certificate.p12 -srcstoretype pkcs12 -destkeystore truststore.jks`
