# (WIP) GnuPG Web of Trust (WIP)

## Introduction

The following outlines a "new" way to realise Web of Trust for GnuPG. The limitations of traditional Web of Trust is described under ["Background information"](#background-information). This new approach consist of:

1. Making sure that public keys are published without later modifications for signature verification to succeed
2. Creation of a class 3 S/MIME key pair issued by [CAcert](http://www.cacert.org)
3. Creation and publication of a detached S/MIME signature for your GnuPG public key
4. GnuPG public key retrieval and signature verification by your communication partner:

```
$ bash s2g.sh pubkey.asc.pkcs7

S/MIME signature's certificate (pubkey.asc.pkcs7):
  - Valid CAcert class 3 certificate: ✅
  - Not expired (until 01/05/2022): ✅
  - Reported "not revoked" (CRL/OCSP): ❌/✅

GnuPG public key:
  - "S/MIME signature verified" found: ✅
  - Fetched via: DANE

GnuPG UID(s) (Matches S/MIME subject? ✅|❌):
  ❌ David Sardari <david.sardari@example.org>
  ✅ David Sardari <david.sardari@example.de>
  ❌ David Sardari <david.sardari@example.eu>

Feel free to import with:
  gpg --import "/tmp/tmp.rkEDaMITRr.asc"

```

## 1. Make sure that public keys are published without later modifications

You need to make sure that your public key that is stored remotely doesn't differ from the local public key that your are going to S/MIME sign later on. Otherwise, signature verification with `s2g.sh` will fail if no unmodified public key is found. I personally rule out any modifications by a third party by providing my public key over DANE and self-hosted WKD where nobody else has write access to.

In order to compare local and remotely stored public keys, create a SHA256 checksum of your local public key file:

```bash
# Replace with your mail address
gpg --export-options export-minimal --armor --export max@mustermann@example.org > pubkey.asc

# pubkey.asc is the file that we are going to S/MIME sign later on
sha256sum pubkey.asc
```

..., compare the checksum with the output provided by following code block:

```bash
# Replace with your mail address
TEST_MAIL="max.mustermann@example.org"
```

Code block:

```bash
TEST_TMPDIR="$(mktemp -d)" && \
for MECHANISM in "dane" "wkd" ${PKA} "cert" "hkps://keys.openpgp.org" "hkps://keys.mailvelope.com" "hkps://keys.gentoo.org" "hkps://keyserver.ubuntu.com"; do
    gpg --homedir "${TEST_TMPDIR}" --no-default-keyring --keyring "${TEST_TMPDIR}/${MECHANISM#*://}.gpg" --auto-key-locate "clear,${MECHANISM}" --locate-external-key "${TEST_MAIL}" >/dev/null 2>&1 && \
    gpg --homedir "${TEST_TMPDIR}" --no-default-keyring --keyring "${TEST_TMPDIR}/${MECHANISM#*://}.gpg" --export-options export-minimal --armor --export "${TEST_MAIL}" > "${TEST_TMPDIR}/${MECHANISM#*://}.asc" 2>/dev/null && \
    echo "${MECHANISM#*://}: $(sha256sum "${TEST_TMPDIR}/${MECHANISM#*://}.asc")"
done | column -t
gpgconf --homedir "${TEST_TMPDIR}" --kill all; echo ""
```

... and make sure that checksums are identical.

## 2. Creation of class 3 S/MIME key pair

You need a class 3 S/MIME certificate signed by [CAcert](http://www.cacert.org):

1. Create your private key for S/MIME and generate a CSR. Unfortunately, [CAcert](http://www.cacert.org) doesn't support ECC. Thus, I am using RSA-4096, having the strongest key strength among algorithms supported by [CAcert](http://www.cacert.org).

```bash
openssl genpkey -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out smime.key
# We can leave the subject and SAN empty,
# because they will be ignored by cacert.org.
openssl req -new -sha256 -key smime.key -subj "/" -out smime.csr
```

2. Get your S/MIME certificate issued:

![certificate request](assets/certificate_request.png)

3. Download your certificate in PEM format and save as `smime.crt`

## 3. GnuPG public key signing with S/MIME

I refrain from using GnuPG's Web of Trust approach. Thus, I am doing a minimal export of my public key excluding all signatures except the most recent self-signature on each user ID.

1. This step can be skipped if you followed the instructions under [caption 1](#1-make-sure-that-public-keys-are-published-without-later-modifications) (recommended). Export your GnuPG public key:

```bash
gpg --export-options export-minimal --armor --export "YOUR KEY ID" > pubkey.asc
```

2. Create a S/MIME detached signature for your GnuPG public key:

```bash
openssl smime -binary -md sha256 -outform pem -sign -signer smime.crt -inkey smime.key -in pubkey.asc -out pubkey.asc.pkcs7
```

3. Publish `pubkey.asc.pkcs7` over the channels of your choice

## 4. S/MIME signature verification by peer

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

... outputs:

> Class 1 SHA256 Fingerprint=07ED BD82 4A49 88CF EF42 15DA 20D4 8C2B 41D7 1529 D7C9 00F5 7092 6F27 7CC2 30C5
>
> Class 3 SHA256 Fingerprint=1BC5 A61A 2C0C 0132 C52B 284F 3DA0 D8DA CF71 7A0F 6C1D DF81 D80B 36EE E444 2869

And, compare them with the hashes published by the CAcert ([HTTP](http://www.cacert.org/index.php?id=3) or [HTTPS](https://www.cacert.org/index.php?id=3)).

To verify your communication partner's GnuPG public key do:

```bash
# Follow the output as you see fit
bash s2g.sh pubkey.asc.pkcs7
```

## Background information

GnuPG's Web of Trust approach is long dead due to:

- [Certificate spamming attacks](https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f)
- disinterest in campaigns such as:
  - [CAcert](http://www.cacert.org): [Signing key](http://www.cacert.org/index.php?id=3) using old `dsa1024` and `elg2048`
  - [DFN](https://web.archive.org/web/20070613205827/https://www.pki.dfn.de/content/index.php?id=pgp): Offline sometime after 2007 and never really for public use (AFAIK)
  - [Heise crypto compaign](https://www.heise.de/security/dienste/Krypto-Kampagne-2111.html): Still publishing to dead SKS keyservers ([see last bullet point](https://www.heise.de/security/dienste/Wie-kann-ich-mitmachen-474837.html)) and [no consideration for ECC keys](https://www.heise.de/security/dienste/Zertifizierungsantrag-474471.html)
- and finally privacy concerns due to [GDPR](https://en.wikipedia.org/wiki/General_Data_Protection_Regulation):

![sks keyserver notification](assets/sks_keyserver_notification.png)
