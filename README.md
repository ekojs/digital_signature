# Digital Signature Instruction Collections
#### Description: All about Digital Signature Instruction
#### Author: Eko Junaidi Salam


## Generate CA Root Key

* Generate 4096bit RSA Key for Root CA
```bash
openssl genrsa -aes256 -out my_ca.enc.key 4096
```

* Generate RSA Key and CSR for CA
```bash
openssl req -new -newkey rsa:4096 -keyout cakey.pem -out careq.pem -config openssl.cnf
```

* Create and self-sign Root CA Certificate from RSA Key
```bash
openssl req -x509 -new -nodes -key my_ca.enc.key -sha256 -days 1024 -out myCA.crt
```

* Create and self-sign V3 Root CA from CSR file
```bash
openssl ca -out cacert.pem -days 2652 -keyfile cakey.pem -selfsign -config openssl.cnf -extensions v3_ca -in careq.pem
```

* Create and Sign end client CSR using Root CA from CSR file
```bash
openssl ca -in serverreq.pem -days 1200 -cert cacert.pem -keyfile cakey.pem -out servercrt.pem -extensions usr_cert -config openssl.cnf
```

* Generate Certificate for client CSR using Root CA
```bash
openssl x509 -req -in my_request.csr -CA myCA.crt -CAkey my_ca.enc.key -CAcreateserial -out my_request.crt -days 730 -sha256
```

* Generate PKCS12 with chain
```bash
openssl pkcs12 -export -in my_request.crt -inkey my_key.enc.key -name "Eko Junaidi Salam" -chain -CAfile myCA.crt -out my_req_with_chain.pfx
```

* Generate PKCS12 with no chain
```bash
openssl pkcs12 -export -in my_request.crt -inkey my_key.enc.key -name "Eko Junaidi Salam" -certfile myCA.crt -out my_req_with_chain.pfx
```

* Generate Key and self-sign Certificate
```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout my.key -out my.crt
```

* Verify end point certificate with CA
```bash
openssl verify -CAfile cacert.pem servercrt.pem
```

* Revoke Certificate
```bash
openssl ca -revoke tescert.crt -config openssl.cnf
```

* Generate Certificate Revocation List (CRL)
```bash
openssl ca -gencrl -config openssl.cnf -out crl.pem
```

* Verify certificate based on CA and CRL
```bash
openssl verify -crl_check -CAfile cacert.pem -CRLfile crl.pem servercrt.pem
```

* Verify ocsp validation
```bash
openssl ocsp -CAfile cacert.pem -issuer issuer.pem -cert yourcert.crt -url http://ocsp.example.com/ -resp_text -noverify
```

## Generate RSA Key

* Generate 2048bit RSA Key
```bash
openssl genrsa -aes256 -out my_key.enc.key 2048
```

* Generate Public Key from RSA Key
```bash
openssl rsa -in my_key.enc.key -pubout -outform pem -out my.pub.pem
```

* Generate CSR from RSA Key
```bash
openssl req -new -days 730 -key my_key.enc.key -text -out my_request.csr
```

* Check CSR content from CSR file
```bash
openssl req -in my_request.csr -noout -text
```

* Generate X509 default PEM Format
```bash
openssl x509 -req -days 730 -in my_request.csr -signkey my_key.enc.key -out my_cert.crt
```

* Generate X509 default PEM Format using V3 Extension and SHA256 Digest
```bash
openssl x509 -req -days 730 -in my_request.csr -signkey my_key.enc.key -out my_cert.crt -sha256 -extfile v3.ext
```

* Extract Public Key from X509 Certificate
```bash
openssl x509 -pubkey -noout -in my_cert.crt > my_pub.pem
```

* Generate SSH Public Key from RSA Key
```bash
ssh-keygen -y -f my_key.enc.key > my_ssh.pub
```

* Generate random key for encryption using aes-256-cbc
```bash
openssl rand -base64 32 -out key.b64
```

* Encrypt the key using public key recipient
```bash
openssl rsautl -encrypt -inkey my.pub.pem -pubin -in key.b64 -out key.b64.enc
```

* Encrypt the file using our key
```bash
openssl enc -aes-256-cbc -salt -in SECRET_FILE -out SECRET_FILE.enc -pass file:./key.b64
```

* Send and Decrypt The encrypted key.b64.enc using private key recipient and your SECRET_FILE.enc using the decrypted key
```bash
openssl rsautl -decrypt -inkey my_key.enc.key -in key.b64.enc -out key.b64

openssl enc -d -aes-256-cbc -in SECRET_FILE.enc -out SECRET_FILE -pass file:./key.b64
```

## Using Free Time Stamp Authority
#### Source from [Free TSA](https://freetsa.org/)

* Download CA and tsa cert
```bash
wget https://freetsa.org/files/tsa.crt
wget https://freetsa.org/files/cacert.pem
```

* Create a tsq (TimeStampRequest) file, which contains a hash of the file you want to sign.
```bash
openssl ts -query -data signed.pdf -no_nonce -sha512 -cert -out signed.tsq
```

* Send the TimeStampRequest to freeTSA.org and receive a tsr (TimeStampResponse) file. 
```bash
curl -H "Content-Type: application/timestamp-query" --data-binary '@signed.tsq' https://freetsa.org/tsr > signed.tsr
```

* With the public Certificates you can verify the TimeStampRequest. 
```bash
openssl ts -verify -in signed.tsr -queryfile signed.tsq -CAfile cacert.pem -untrusted tsa.crt
```

* URL Screenshooter from TSA
```bash
curl --data "screenshot=https://www.fsf.org/&delay=n" https://freetsa.org/screenshot.php > screenshot.pdf
```


## Generate ECDSA Key

* Generate Encrypted EC key
```bash
openssl ecparam -genkey -name secp256k1 | openssl ec -aes256 -out my_ec.enc.key
```

* Generate Public Key from EC Key
```bash
openssl ec -in my_ec.enc.key -pubout -out my_ecpub.pem
```

* Generate CSR from EC Key
```bash
openssl req -new -sha256 -key my_ec.enc.key -days 730 -text -out my_ec.csr
```


## My Certificate OpenSSH
* Create SSH Public Key from OpenSSL Key
```bash
ssh-keygen -y -f my_key.enc.key > my-ssh.pub
```

* Show Fingerprint of SSH Public Key
```bash
ssh-keygen -lv -E md5 -f my_ssh.pub
```


## My Certificate X509

* Generate CSR from Certificate
```bash
openssl x509 -x509toreq -in .\my_cert.crt -signkey .\my_key.enc.key -out .\my_request.csr
```

* Renew expired certificate
```bash
openssl x509 -req -days 365 -in .\my_request.csr -signkey .\my_key.enc.key -out .\my_cert_renew.crt
```

* Get unencrypted key from encrypted private key
```bash
openssl rsa -in .\my_key.enc.key -out hasil.key
```

* Generate PKCS12 from Certificate
```bash
openssl pkcs12 -export -in .\my_cert_renew.crt -inkey .\my_key.enc.key -out .\my_cert_renew.p12
 ```

* Extract Private Key (PEM) from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nocerts -out .\my_cert.pem
```

* Extract Private Key from PEM file using DES3 encrypted
```bash
openssl rsa -in .\my_cert.pem -des3 -out .\my_key.enc.key
```

* Extract Client Certificate from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nokeys -clcerts -out .\my_cert.crt
```

* Extract CA Certificate from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nokeys -cacerts -out .\my_cert.crt
```

* Create Public Key from RSA Private Key
```bash
openssl rsa -in .\my_key.enc.key -pubout -out my_key.pub
```

* Sign a digest with RSA Private Key
```bash
openssl dgst -sha256 -sign .\my_key.enc.key -out .\README.md.sig .\README.md
```

* Verify a Signed Digest using Public Key
```bash
openssl dgst -sha256 -verify .\my_key.pub -signature .\README.md.sig .\README.md
```


## My Certificate gpg (GnuPG) 1.4.20
```bash
Supported algorithms:
Pubkey: RSA, RSA-E, RSA-S, ELG-E, DSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: MD5, SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2
Read : https://futureboy.us/pgp.html
```

* Generate GPG Public & Private Key
```bash
gpg -i --gen-key
```

* Change key
```bash
gpg -i -edit-key user_id
```

* Change cipher algorithms
```bash
gpg --cipher-algo name -ca your_file
```

* Using Stronger Algorithms
```bash
gpg -i --edit-key user_id 
help
showpref
setpref AES256 CAMELLIA256 AES192 CAMELLIA192 AES CAMELLIA128 TWOFISH CAST5 3DES SHA512 SHA384 SHA256 SHA224 SHA1 RIPEMD160 ZLIB BZIP2 ZIP Uncompressed
save
```

* Backup Secret Key and Subkey
```bash
gpg --export-secret-key -a -o key.asc
gpg --export-secret-subkeys -a -o subkey.asc
```

* Backup Public Key
```bash
gpg -o pub.gpg -a --export eko_junaidisalam@live.com
```

* Encrypt using symmetric cipher
```bash
gpg --cipher-algo aes256 -ca filename
```

* Decrypt a file
```bash
gpg filename
```

* Sign and armored a file
```bash
gpg -o hasil.asc -sa filename
```

* Verify a signed armored file
```bash
gpg --verify hasil.asc
```

* Create revocation certificate
```bash
gpg -o my_revocation_cert --gen-revoke key_id
```

* Separate Master Keypair to Laptop Keypair
```bash
mkdir /tmp/gpg
sudo mount -t tmpfs -o size=1M tmpfs /tmp/gpg
gpg --export-secret-subkeys key_id > /tmp/gpg/subkeys
gpg --delete-secret-key key_id
gpg --import /tmp/gpg/subkeys
sudo umount /tmp/gpg
rm -rf /tmp/gpg

gpg -K

# You should see like this 'sec#  2048R/C774674E 2016-03-10' not 'sec  2048R/C774674E 2016-03-10', it means you're successfully separate subkey from the keypair located in your keyring.
```

* Show photo in gpg
```bash
# You must set photo-viewer "eog %i" in your gpg.conf file

gpg --list-options show-photos --fingerprint ekojs
```

* Sign someone key
```bash
gpg -u yourkey --sign-key --ask-cert-level someone@email.com
```


## Check corresponding RSA Private Key & Public Key
* For RSA & X509
```bash
openssl rsa -in .\my_key.enc.key -modulus -noout | openssl md5
openssl x509 -in .\my_cert.crt -modulus -noout | openssl md5
```

* For RSA & SSH Pub Key
```bash
ssh-keygen -y -f my_key.enc.key
cat my_ssh.pub
```

* Check pub fingerprint
```bash
ssh-keygen -lv -E md5 -f my_ssh.pub
openssl x509 -noout -fingerprint -md5 -in .\my_cert.crt
```

* For Pub & priv Key OpenPGP, you can check it in `keyid` values.
```bash
gpg --list-packets pub_key.asc | head
gpg --list-packets priv_key.asc | head
```

## Check IMAP via SSL uses port 993
```
openssl s_client -showcerts -connect mail.example.com:993
```

## Check POP3 via SSL uses port 995
```
openssl s_client -showcerts -connect mail.example.com:995
```

## Check SMTP via SSL uses port 465
```
openssl s_client -showcerts -connect mail.example.com:465
```

## Check SMTP via TLS/StartTLS uses port 587
```
openssl s_client -starttls smtp -showcerts -connect mail.example.com:587
```

## Create certificate using lets encrypt
#### some reading : [Generate wildcard ssl using lets encrypt](https://medium.com/@saurabh6790/generate-wildcard-ssl-certificate-using-lets-encrypt-certbot-273e432794d7)
```bash
apt install letsencrypt
certbot certonly --manual --preferred-challenges=dns --email your-email@gmail.com --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d *.example.com
```


## Generate Certificate using Keytool from Java
* Create self-sign Certificate
```bash
keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365 -v -keyalg RSA -keysize 2048 -keystore keystore.p12 
```

* Check detail keystore content
```bash
keytool -keystore keystore.p12 -list -v
```

* Import another PKCS12 to keystore
```bash
keytool -importkeystore -srcstoretype pkcs12 -srckeystore cert.p12 -destkeystore keystore.p12 -srcalias 1 -destalias youralias
```

## Create Perfect Keypair in OpenPGP
* Generate key RSA-RSA 4096 bits keysize
* Add photo to the key
* Add subkey to complete flag i.e : SC, S, E
* Use Stronger Algorithms
* Creating Revocation Certificate if your master keypair gets lost or stolen. This file is only way to tell everyone to ignore the stolen key.
* Separate Master keypair to laptop keypair


#### Passphrase for all key is `12345`


#### Note:
Please feel free to add useful instruction to this repo. Silahkan bebas untuk menambahkan perintah-perintah yang berguna dalam Digital Signature pada repo ini.
