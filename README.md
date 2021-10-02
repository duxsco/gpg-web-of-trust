# (WIP) GnuPG Web of Trust (WIP)

## Background

GnuPG's Web of Trust approach is long dead due to:

- [Certificate spamming attacks](https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f)
- disinterest in campaigns such as:
  - [CAcert](http://www.cacert.org): [Signing key](http://www.cacert.org/index.php?id=3) using old `dsa1024` and `elg2048`
  - [DFN](https://web.archive.org/web/20070613205827/https://www.pki.dfn.de/content/index.php?id=pgp): Offline sometime after 2007 and never really for public use (AFAIK)
  - [Heise crypto compaign](https://www.heise.de/security/dienste/Krypto-Kampagne-2111.html): Still publishing to dead SKS keyservers ([see last bullet point](https://www.heise.de/security/dienste/Wie-kann-ich-mitmachen-474837.html)) and [no consideration for ECC keys](https://www.heise.de/security/dienste/Zertifizierungsantrag-474471.html)
- and finally privacy concerns due to [GDPR](https://en.wikipedia.org/wiki/General_Data_Protection_Regulation):

![sks keyserver notification](assets/sks_keyserver_notification.png)

## Direct trust approach

I created the repo [gpg-config-and-scripts](https://github.com/duxco/gpg-config-and-scripts) with configuration files that enforce setting key validity directly without any dependence on Web of Trust. Furthermore, scripts are provided to:

  - check for public key delivery options (e.g. DANE, WKD) and pull keys from a suitable source ([pull.sh](https://github.com/duxco/gpg-config-and-scripts/blob/main/bin/pull.sh))
  - display man pages while highlighting defaults (in yellow) and options that have been set in the configuration file (in red) ([man.sh](https://github.com/duxco/gpg-config-and-scripts/blob/main/bin/man.sh))
  - manage the public key store ([pubkey.sh](https://github.com/duxco/gpg-config-and-scripts/blob/main/bin/pubkey.sh))

## Signing GnuPG public keys with S/MIME

But, I still had the wish to provide some verification mechanism while publishing my GnuPG public key. Thus, I decided to build upon class 3 S/MIME certificates issued by [CAcert](http://www.cacert.org) to sign my GnuPG public keys.

### S/MIME keypair creation

To get started you first have to get a valid certificate issued:

1. First, you have to create your private key for S/MIME and generate a CSR. Unfortunately, [CAcert](http://www.cacert.org) doesn't support ECC. Thus, I am using RSA3072, the next best option (IMHO).

```bash
( umask 0177 && openssl genrsa -aes256 -out smime.key 3072 )
# We can leave the subject and SAN empty,
# because they will be ignored by cacert.org.
openssl req -new -sha256 -key smime.key -subj "/" -out smime.csr
```

2. Get your S/MIME certificate issued:

![certificate request](assets/certificate_request.png)

3. Download your certificate:

![certificate download](assets/certificate_download.png)

4. Create a PKCS 12 file:

```bash
openssl pkcs12 -export -in smime.crt -inkey smime.key -out smime.pkcs12
```

### GnuPG keypair signing

I refrain from using GnuPG's Web of Trust approach. Thus, I am doing a minimal export of my public key excluding all signatures except the most recent self-signature on each user ID.

1. Export your GnuPG public key:

```bash
gpg --export-options export-minimal --export --armor "YOUR KEY ID" > pubkey.asc
```

2. Sign your GnuPG public key:

```bash
openssl pkcs12 -in smime.pkcs12 -nodes | openssl smime -sign -signer - -in pubkey.asc -out pubkey.asc.msg
```

`pubkey.asc.msg` is the S/MIME signed GnuPG public key file you can publish.

## Verification of S/MIME signature and GnuPG public key import

### ⚠ Disclaimer ⚠

`s2g.sh` is still WIP. Currently, I cannot fully test `s2g.sh`:

- I am currently trying to recover my old [CAcert](http://www.cacert.org) account using [Password Recovery with Assurance](https://wiki.cacert.org/FAQ/LostPasswordOrAccount#Password_Recovery_with_Assurance) in order to be able to get a class 3 S/MIME certificate issued again.
- https://crl.cacert.org delivers an expired intermediate certificate ([see](https://www.ssllabs.com/ssltest/analyze.html?d=crl.cacert.org&latest))
- OCSP responses are signed by an expired certificate:

```bash
openssl ocsp -CAfile cacert.org_class1.crt -issuer cacert.org_class1.crt -cert cacert.org_class1.crt -url http://ocsp.cacert.org -text | openssl x509 -dates -noout
Response Verify Failure
139665196160384:error:27069065:OCSP routines:OCSP_basic_verify:certificate verify error:crypto/ocsp/ocsp_vfy.c:92:Verify error:certificate has expired
139665196160384:error:27069065:OCSP routines:OCSP_basic_verify:certificate verify error:crypto/ocsp/ocsp_vfy.c:92:Verify error:certificate has expired
notBefore=Aug 25 14:12:48 2019 GMT
notAfter=Aug 24 14:12:48 2021 GMT
```

The expected behaviour for class 1 certificates is like that shown for class 3:

```bash
echo | openssl s_client -CAfile cacert.org_class3.crt -servername www.cacert.org -connect www.cacert.org:443 2>/dev/null | openssl x509 | openssl ocsp -CAfile cacert.org_class1.crt -issuer cacert.org_class3.crt -cert - -url http://ocsp.cacert.org -text | openssl x509 -dates -noout
Response verify OK
notBefore=Aug 24 20:34:34 2021 GMT
notAfter=Aug 24 20:34:34 2023 GMT
```

I already notified CAcert support of the last two problems and awaiting a response.

### `s2g.sh` - S/MIME signed GnuPG

[CAcert](http://www.cacert.org) class 1 and class 3 root certificates have been integrated in `s2g.sh` (**S**/IME **s**igned **G**nuPG). To verify them print their fingerprint ([credits](https://kdecherf.com/blog/2015/04/10/show-the-certificate-chain-of-a-local-x509-file/)):

```bash
cat s2g.sh | awk -F'\n' '
        BEGIN {
            ind = 1
            showcert = "openssl x509 -fingerprint -noout -sha256"
        }

        /-----BEGIN CERTIFICATE-----/ {
            printf "Class %d ", ind
        }

        {
            if (ind == 1 || ind == 3) {
                printf $0"\n" | showcert
            }
        }

        /-----END CERTIFICATE-----/ {
            close(showcert)
            ind ++
            ind ++
        }
    ' | sed 's/\([^:]*:[^:]*\):/\1 /g' | tr -d ':'
```

And, compare them with the hashes published by the CAcert ([HTTP](http://www.cacert.org/index.php?id=3) or [HTTPS](https://www.cacert.org/index.php?id=3)).

To verify and import your communication partner's GnuPG public key do:

```bash
# Verify
bash s2g.sh pubkey.asc.msg

# If verification succeded...
gpg --import pubkey.asc.msg
```
