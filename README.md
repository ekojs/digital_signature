#Digital Signature Instruction Collections
####Description: All about Digital Signature Instruction
####Author: Eko Junaidi Salam


##Generate RSA Key

1.Generate 2048bit RSA Key
```bash
openssl genrsa -aes256 -out my_key.enc.key 2048
```

2.Generate CSR from RSA Key
```bash
openssl req -new -days 730 -key my_key.enc.key -text -out my_request.csr
```

3.Generate X509 default PEM Format
```bash
openssl x509 -req -days 730 -in my_request.csr -signkey my_key.enc.key -out my_cert.crt
```

4.Generate SSH Public Key from RSA Key
```bash
ssh-keygen -y -f my_key.enc.key > my_ssh.pub
```


##My Certificate X509

1.Generate CSR from Certificate
```bash
openssl x509 -x509toreq -in .\my_cert.crt -signkey .\my_key.enc.key -out .\my_request.csr
```

2.Renew expired certificate
```bash
openssl x509 -req -days 365 -in .\my_request.csr -signkey .\my_key.enc.key -out .\my_cert_renew.crt
```

3.Get unencrypted key from encrypted private key
```bash
openssl rsa -in .\my_key.enc.key -out hasil.key
```

4.Generate PKCS12 from Certificate
```bash
openssl pkcs12 -export -in .\my_cert_renew.crt -inkey .\my_key.enc.key -out .\my_cert_renew.p12
```

5.Extract Private Key (PEM) from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nocerts -out .\my_cert.pem
```

6.Extract Private Key from PEM file using DES3 encrypted
```bash
openssl rsa -in .\my_cert.pem -des3 -out .\my_key.enc.key
```

7.Extract Client Certificate from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nokeys -clcerts -out .\my_cert.crt
```

8.Extract CA Certificate from PKCS12
```bash
openssl pkcs12 -in .\my_cert_renew.p12 -nokeys -cacerts -out .\my_cert.crt
```


##My Certificate gpg (GnuPG) 1.4.20
```bash
Supported algorithms:
Pubkey: RSA, RSA-E, RSA-S, ELG-E, DSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: MD5, SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2
Read : https://futureboy.us/pgp.html
```

1.Change key
```bash
gpg -i -edit-key user_id
```

2.Change cipher algorithms
```bash
gpg --cipher-algo name -ca your_file
```

3.Using Stronger Algorithms
```bash
gpg -i --edit-key user_id 
help
showpref
setpref AES256 CAMELLIA256 AES192 CAMELLIA192 AES CAMELLIA128 TWOFISH CAST5 3DES SHA512 SHA384 SHA256 SHA224 SHA1 RIPEMD160 ZLIB BZIP2 ZIP Uncompressed
save
```

4.Backup Secret Key
```bash
gpg --export-secret-key -a -o key.asc
```

5.Backup Public Key
```bash
gpg -o pub.gpg -a --export eko_junaidisalam@live.com
```

6.Encrypt using symmetric cipher
```bash
gpg --cipher-algo aes256 -ca filename
```

7.Decrypt a file
```bash
gpg filename
```

8.Sign and armored a file
```bash
gpg -o hasil.asc -sa filename
```



##My Certificate OpenSSH
1.Create SSH Public Key from OpenSSL Key
```bash
ssh-keygen -y -f my_key.enc.key > my-ssh.pub
```

2.Show Fingerprint of SSH Public Key
```bash
ssh-keygen -lv -E md5 -f my_ssh.pub
```



##Check corresponding RSA Private Key & Public Key
1.For RSA & X509
```bash
openssl rsa -in .\my_key.enc.key -modulus -noout | openssl md5
openssl x509 -in .\my_cert.crt -modulus -noout | openssl md5
```

2.For RSA & SSH Pub Key
```bash
ssh-keygen -y -f my_key.enc.key
cat my_ssh.pub
```

3.Check pub fingerprint
```bash
ssh-keygen -lv -E md5 -f my_ssh.pub
openssl x509 -noout -fingerprint -md5 -in .\my_cert.crt
```



#### Note:
Please feel free to add useful instruction to this repo. Silahkan bebas untuk menambahkan perintah-perintah yang berguna dalam Digital Signature pada repo ini.
