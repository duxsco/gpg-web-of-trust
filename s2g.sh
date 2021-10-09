#!/usr/bin/env bash

set -euo pipefail

CLASS1_ROOT_CRT="
-----BEGIN CERTIFICATE-----
MIIG7jCCBNagAwIBAgIBDzANBgkqhkiG9w0BAQsFADB5MRAwDgYDVQQKEwdSb290
IENBMR4wHAYDVQQLExVodHRwOi8vd3d3LmNhY2VydC5vcmcxIjAgBgNVBAMTGUNB
IENlcnQgU2lnbmluZyBBdXRob3JpdHkxITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRA
Y2FjZXJ0Lm9yZzAeFw0wMzAzMzAxMjI5NDlaFw0zMzAzMjkxMjI5NDlaMHkxEDAO
BgNVBAoTB1Jvb3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEi
MCAGA1UEAxMZQ0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJ
ARYSc3VwcG9ydEBjYWNlcnQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAziLA4kZ97DYoB1CW8qAzQIxL8TtmPzHlawI229Z89vGIj053NgVBlfkJ
8BLPRoZzYLdufujAWGSuzbCtRRcMY/pnCujW0r8+55jE8Ez64AO7NV1sId6eINm6
zWYyN3L69wj1x81YyY7nDl7qPv4coRQKFWyGhFtkZip6qUtTefWIonvuLwphK42y
fk1WpRPs6tqSnqxEQR5YYGUFZvjARL3LlPdCfgv3ZWiYUQXw8wWRBB0bF4LsyFe7
w2t6iPGwcswlWyCR7BYCEo8y6RcYSNDHBS4CMEK4JZwFaz+qOqfrU0j36NK2B5jc
G8Y0f3/JHIJ6BVgrCFvzOKKrF11myZjXnhCLotLddJr3cQxyYN/Nb5gznZY0dj4k
epKwDpUeb+agRThHqtdB7Uq3EvbXG4OKDy7YCbZZ16oE/9KTfWgu3YtLq1i6L43q
laegw1SJpfvbi1EinbLDvhG+LJGGi5Z4rSDTii8aP8bQUWWHIbEZAWV/RRyH9XzQ
QUxPKZgh/TMfdQwEUfoZd9vUFBzugcMd9Zi3aQaRIt0AUMyBMawSB3s42mhb5ivU
fslfrejrckzzAeVLIL+aplfKkQABi6F1ITe1Yw1nPkZPcCBnzsXWWdsC4PDSy826
YreQQejdIOQpvGQpQsgi3Hia/0PsmBsJUUtaWsJx8cTLc6nloQsCAwEAAaOCAX8w
ggF7MB0GA1UdDgQWBBQWtTIb1Mfz4OaO873SsDrusjkY0TAPBgNVHRMBAf8EBTAD
AQH/MDQGCWCGSAGG+EIBCAQnFiVodHRwOi8vd3d3LmNhY2VydC5vcmcvaW5kZXgu
cGhwP2lkPTEwMFYGCWCGSAGG+EIBDQRJFkdUbyBnZXQgeW91ciBvd24gY2VydGlm
aWNhdGUgZm9yIEZSRUUgaGVhZCBvdmVyIHRvIGh0dHA6Ly93d3cuY2FjZXJ0Lm9y
ZzAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vY3JsLmNhY2VydC5vcmcvcmV2b2tl
LmNybDAzBglghkgBhvhCAQQEJhYkVVJJOmh0dHA6Ly9jcmwuY2FjZXJ0Lm9yZy9y
ZXZva2UuY3JsMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAYYWaHR0cDovL29j
c3AuY2FjZXJ0Lm9yZzAfBgNVHSMEGDAWgBQWtTIb1Mfz4OaO873SsDrusjkY0TAN
BgkqhkiG9w0BAQsFAAOCAgEAR5zXs6IX01JTt7Rq3b+bNRUhbO9vGBMggczo7R0q
Ih1kdhS6WzcrDoO6PkpuRg0L3qM7YQB6pw2V+ubzF7xl4C0HWltfzPTbzAHdJtja
JQw7QaBlmAYpN2CLB6Jeg8q/1Xpgdw/+IP1GRwdg7xUpReUA482l4MH1kf0W0ad9
4SuIfNWQHcdLApmno/SUh1bpZyeWrMnlhkGNDKMxCCQXQ360TwFHc8dfEAaq5ry6
cZzm1oetrkSviE2qofxvv1VFiQ+9TX3/zkECCsUB/EjPM0lxFBmu9T5Ih+Eqns9i
vmrEIQDv9tNyJHuLsDNqbUBal7OoiPZnXk9LH+qb+pLf1ofv5noy5vX2a5OKebHe
+0Ex/A7e+G/HuOjVNqhZ9j5Nispfq9zNyOHGWD8ofj8DHwB50L1Xh5H+EbIoga/h
JCQnRtxWkHP699T1JpLFYwapgplivF4TFv4fqp0nHTKC1x9gGrIgvuYJl1txIKmx
XdfJzgscMzqpabhtHOMXOiwQBpWzyJkofF/w55e0LttZDBkEsilV/vW0CJsPs3eN
aQF+iMWscGOkgLFlWsAS3HwyiYLNJo26aqyWPaIdc8E4ck7Sk08WrFrHIK3EHr4n
1FZwmLpFAvucKqgl0hr+2jypyh5puA3KksHF3CsUzjMUvzxMhykh9zrMxQAHLBVr
Gwc=
-----END CERTIFICATE-----
"

CLASS3_ROOT_CRT="
-----BEGIN CERTIFICATE-----
MIIGPTCCBCWgAwIBAgIDFOIoMA0GCSqGSIb3DQEBDQUAMHkxEDAOBgNVBAoTB1Jv
b3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEiMCAGA1UEAxMZ
Q0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYSc3VwcG9y
dEBjYWNlcnQub3JnMB4XDTIxMDQxOTEyMTgzMFoXDTMxMDQxNzEyMTgzMFowVDEU
MBIGA1UEChMLQ0FjZXJ0IEluYy4xHjAcBgNVBAsTFWh0dHA6Ly93d3cuQ0FjZXJ0
Lm9yZzEcMBoGA1UEAxMTQ0FjZXJ0IENsYXNzIDMgUm9vdDCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAKtJNRFIfNImflOUz0Op3SjXQiqL84d4GVh8D57a
iX3h++tykA10oZZkq5+gJJlz2uJVdscXe/UErEa4w75/ZI0QbCTzYZzA8pD6Ueb1
aQFjww9W4kpCz+JEjCUoqMV5CX1GuYrz6fM0KQhF5Byfy5QEHIGoFLOYZcRD7E6C
jQnRvapbjZLQ7N6QxX8KwuPr5jFaXnQ+lzNZ6MMDPWAzv/fRb0fEze5ig1JuLgia
pNkVGJGmhZJHsK5I6223IeyFGmhyNav/8BBdwPSUp2rVO5J+TJAFfpPBLIukjmJ0
FXFuC3ED6q8VOJrU0gVyb4z5K+taciX5OUbjchs+BMNkJyIQKopPWKcDrb60LhPt
XapI19V91Cp7XPpGBFDkzA5CW4zt2/LP/JaT4NsRNlRiNDiPDGCbO5dWOK3z0luL
oFvqTpa4fNfVoIZwQNORKbeiPK31jLvPGpKK5DR7wNhsX+kKwsOnIJpa3yxdUly6
R9Wb7yQocDggL9V/KcCyQQNokszgnMyXS0XvOhAKq3A6mJVwrTWx6oUrpByAITGp
rmB6gCZIALgBwJNjVSKRPFbnr9s6JfOPMVTqJouBWfmh0VMRxXudA/Z0EeBtsSw/
LIaRmXGapneLNGDRFLQsrJ2vjBDTn8Rq+G8T/HNZ92ZCdB6K4/jc0m+YnMtHmJVA
BfvpAgMBAAGjgfIwge8wDwYDVR0TAQH/BAUwAwEB/zBhBggrBgEFBQcBAQRVMFMw
IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLkNBY2VydC5vcmcvMCwGCCsGAQUFBzAC
hiBodHRwOi8vd3d3LkNBY2VydC5vcmcvY2xhc3MzLmNydDBFBgNVHSAEPjA8MDoG
CysGAQQBgZBKAgMBMCswKQYIKwYBBQUHAgEWHWh0dHA6Ly93d3cuQ0FjZXJ0Lm9y
Zy9jcHMucGhwMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vd3d3LmNhY2VydC5v
cmcvY2xhc3MzLmNybDANBgkqhkiG9w0BAQ0FAAOCAgEAxh6td1y0KJvRyI1EEsC9
dnYEgyEH+BGCf2vBlULAOBG1JXCNiwzB1Wz9HBoDfIv4BjGlnd5BKdSLm4TXPcE3
hnGjH1thKR5dd3278K25FRkTFOY1gP+mGbQ3hZRB6IjDX+CyBqS7+ECpHTms7eo/
mARN+Yz5R3lzUvXs3zSX+z534NzRg4i6iHNHWqakFcQNcA0PnksTB37vGD75pQGq
eSmx51L6UzrIpn+274mhsaFNL85jhX+lKuk71MGjzwoThbuZ15xmkITnZtRQs6Hh
LSIqJWjDILIrxLqYHehK71xYwrRNhFb3TrsWaEJskrhveM0Os/vvoLNkh/L3iEQ5
/LnmLMCYJNRALF7I7gsduAJNJrgKGMYvHkt1bo8uIXO8wgNV7qoU4JoaB1ML30QU
qGcFr0TI06FFdgK2fwy5hulPxm6wuxW0v+iAtXYx/mRkwQpYbcVQtrIDvx1CT1k5
0cQxi+jIKjkcFWHw3kBoDnCos0/ukegPT7aQnk2AbL4c7nCkuAcEKw1BAlSETkfq
i5btdlhh58MhewZv1LcL5zQyg8w1puclT3wXQvy8VwPGn0J/mGD4gLLZ9rGcHDUE
CokxFoWk+u5MCcVqmGbsyG4q5suS3CNslsHURfM8bQK4oLvHR8LCHEBMRcdFBn87
cSvOK6eB1kdGKLA8ymXxZp8=
-----END CERTIFICATE-----
"

function getCRL() {
    # Certificate suite list created with:
    # openssl ciphers -v -s | grep AEAD | grep ECDHE | awk '{print $1}' | paste -d: -s -
    #
    # In case of tlsv1.3, we take every siphcer suite.

    echo "${CLASS1_ROOT_CRT}" | \
    curl \
        --fail --silent --show-error \
        --cacert /dev/stdin \
        --cert-status --proto '=https' --tlsv1.2 \
        --ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256" \
        "$(openssl x509 -noout -ext crlDistributionPoints <<<"$1" | grep -Po 'URI:\K.*' | sed 's#http://#https://#')" | \
    openssl crl -inform DER -outform PEM
}

function getCRTsubjectValue() {
    openssl x509 \
        -noout \
        -subject \
        -nameopt esc_ctrl,esc_msb,sep_multiline,lname <<<"${CRT}" | \
    grep -Po "^[[:space:]]*$1=\K.*"
}

if [ ! -f "$1" ] || ! openssl pkcs7 -noout -in "$1"; then
    echo -e "\nNo PKCS #7 file provided, e.g. \"bash ${0##*/} pubkey.asc.pkcs7\". Aborting...\n"
else
    CRT="$(openssl pkcs7 -print_certs -in "$1" | openssl x509)"
    CRT_NAME="$(getCRTsubjectValue "commonName")"
    CRT_MAIL="$(getCRTsubjectValue "emailAddress")"

    CLASS1_CRL_PEM="$(getCRL "${CLASS1_ROOT_CRT}")"
    CLASS3_CRL_PEM="$(getCRL "${CLASS3_ROOT_CRT}")"

    TMP_GPG_HOMEDIR="$(mktemp -d)"
    GPG_PUBKEY="$(mktemp)"
    mv "${GPG_PUBKEY}" "${GPG_PUBKEY}.asc"

    grep -q '^gpg (GnuPG) 2\.2\.' < <(gpg --homedir "${TMP_GPG_HOMEDIR}" --version) && \
    PKA="pka" || \
    PKA=""

    openssl verify \
        -CAfile <(echo "${CLASS1_ROOT_CRT}") \
        -untrusted <(echo "${CLASS3_ROOT_CRT}") \
        <<<"${CRT}" >/dev/null 2>&1 && \
    CACERT_CLASS3_CRT="✔" || \
    CACERT_CLASS3_CRT="✘"

    openssl x509 \
        -noout \
        -checkend 0 <<<"${CRT}" >/dev/null 2>&1 && \
    NOT_EXPIRED="✔" || \
    NOT_EXPIRED="✘"

    openssl verify \
        -crl_check_all \
        -CAfile <(echo "${CLASS1_ROOT_CRT}") \
        -untrusted <(echo "${CLASS3_ROOT_CRT}") \
        -CRLfile <(echo "${CLASS1_CRL_PEM}") \
        -CRLfile <(echo "${CLASS3_CRL_PEM}") \
        <<<"${CRT}" >/dev/null 2>&1 && \
    CRL="✔" || \
    CRL="✘"

    openssl ocsp \
        -CAfile <(echo "${CLASS1_ROOT_CRT}") \
        -issuer <(echo "${CLASS3_ROOT_CRT}") \
        -cert <(echo "${CRT}") \
        -url "$(
            openssl x509 \
                -noout \
                -ocsp_uri <<<"${CRT}" | \
            sed 's#^http://#https://#')" >/dev/null 2>&1 && \
    OCSP="✔" || \
    OCSP="✘"

    for MECHANISM in "dane" "wkd" ${PKA} "cert" "hkps://keys.openpgp.org" "hkps://keys.mailvelope.com" "hkps://keys.gentoo.org" "hkps://keyserver.ubuntu.com"; do
        # shellcheck disable=SC2015
        gpg --homedir "${TMP_GPG_HOMEDIR}" --no-default-keyring --keyring "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.gpg" \
            --auto-key-locate "clear,${MECHANISM}" \
            --locate-external-key "${CRT_MAIL}" >/dev/null 2>&1 && \
        gpg --homedir "${TMP_GPG_HOMEDIR}" --no-default-keyring --keyring "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.gpg" \
            --export-options export-minimal \
            --armor \
            --export "${CRT_MAIL}" > "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.asc" 2>/dev/null && \
        openssl smime \
            -CAfile <<<"${CLASS3_ROOT_CRT}" \
            -verify \
            -in "$1" \
            -content "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.asc" \
            -inform pem >/dev/null 2>&1 && \
        cat "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.asc" > "${GPG_PUBKEY}.asc" && \
        GPG_PUBKEY_SOURCE="${MECHANISM}" && \
        break || \
        GPG_PUBKEY_SOURCE=""
    done

    # shellcheck disable=SC2076
    [ -n "${GPG_PUBKEY_SOURCE}" ] && \
    readarray -t GPG_UID < <(
        gpg \
            --homedir "${TMP_GPG_HOMEDIR}" --no-default-keyring --keyring "${TMP_GPG_HOMEDIR}/${MECHANISM#*://}.gpg" \
            --with-colons \
            --show-keys "${GPG_PUBKEY}.asc" 2>/dev/null | \
        grep "^uid" | \
        cut -d: -f10
    ) >/dev/null 2>&1 && \
    [[ " ${GPG_UID[*]} " =~ " ${CRT_NAME} <${CRT_MAIL}> " ]] && \
    SUBJECT_UID_MATCH="✔" || \
    SUBJECT_UID_MATCH="✘"

    cat <<EOF

S/MIME certificate:
  - CAcert class3 certificate: ${CACERT_CLASS3_CRT}
  - Not expired: ${NOT_EXPIRED}
  - Not revoked (CRL/OCSP): ${CRL}/${OCSP}

GnuPG public key:
  - Fetched from: ${GPG_PUBKEY_SOURCE}
  - CRT Subject and GnuPG UID match: ${SUBJECT_UID_MATCH}

S/MIME certificate subject:
  - CommonName: ${CRT_NAME}
  - E-Mail:     ${CRT_MAIL}

EOF

    if [ -n "${GPG_PUBKEY_SOURCE}" ]; then
        cat <<EOF
GnuPG UID(s):
$(printf '  - %s\n' "${GPG_UID[@]}")

Feel free to import with:
  gpg --import "${GPG_PUBKEY}.asc"

EOF
    fi
fi
