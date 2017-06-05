# Digital Signature Instruction Collections
#### Description: All about Digital Signature Instruction
#### Author: Eko Junaidi Salam


## Generate RSA Key

* Generate 2048bit RSA Key
```bash
openssl genrsa -aes256 -out my_key.enc.key 2048
```

* Generate CSR from RSA Key
```bash
openssl req -new -days 730 -key my_key.enc.key -text -out my_request.csr
```

* Generate X509 default PEM Format
```bash
openssl x509 -req -days 730 -in my_request.csr -signkey my_key.enc.key -out my_cert.crt
```

* Generate SSH Public Key from RSA Key
```bash
ssh-keygen -y -f my_key.enc.key > my_ssh.pub
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


## Create Perfect Keypair in OpenPGP
* Generate key RSA-RSA 4096 bits keysize
* Add photo to the key
* Add subkey to complete flag i.e : SC, S, E
* Use Stronger Algorithms
* Creating Revocation Certificate if your master keypair gets lost or stolen. This file is only way to tell everyone to ignore the stolen key.
* Separate Master keypair to laptop keypair


#### Passphrase for RSA example key [`my_key.enc.key`](https://github.com/ekojs/digital_signature/blob/master/X509/my_key.enc.key) in this repo is `12345`
#### Passphrase for OpenPGP example key [`my_secret_key.asc`](https://github.com/ekojs/digital_signature/blob/master/OpenPGP/my_secret_key.asc) in this repo is `12345`


#### Note:
Please feel free to add useful instruction to this repo. Silahkan bebas untuk menambahkan perintah-perintah yang berguna dalam Digital Signature pada repo ini.
