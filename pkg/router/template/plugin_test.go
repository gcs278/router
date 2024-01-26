package templaterouter

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router/controller"
)

const (
	// openssl req -x509 -sha256 -newkey rsa:1024 -days 3650 -keyout exampleca.key -out exampleca.crt -addext "keyUsage=cRLSign, digitalSignature, keyCertSign" -addext "extendedKeyUsage=serverAuth, clientAuth" -nodes -subj '/C=US/ST=SC/L=Default City/O=Default Company Ltd/OU=Test CA/CN=www.exampleca.com/emailAddress=example@example.com'
	// openssl req -new -key testCertPrivateKey.key -nodes -out testCAUnknownCertificate.csr -subj '/CN=www.example.com/ST=SC/C=US/emailAddress=example@example.com/O=Example/OU=Example'
	// openssl x509 -req -days 3650 -sha256 -in testCAUnknownCertificate.csr -CA exampleca.crt -CAcreateserial -CAkey exampleca.key -extensions ext -extfile <(echo $'[ext]\nbasicConstraints = CA:FALSE') -out example.crt
	//
	// Signature Algorithm: sha256WithRSAEncryption
	// Issuer: C = US, ST = SC, L = Default City, O = Default Company Ltd, OU = Test CA, CN = www.exampleca.com, emailAddress = example@example.com
	// Validity
	//    Not Before: Jan 10 19:00:04 2024 GMT
	//    Not After : Jan  7 19:00:04 2034 GMT
	// Subject: CN = www.example.com, ST = SC, C = US, emailAddress = example@example.com, O = Example, OU = Example
	// Key = testCertPrivateKey
	// CA = Unknown
	testCAUnknownCertificate = `-----BEGIN CERTIFICATE-----
MIIC9DCCAl2gAwIBAgIUTWv/Z/7lOkdCELulnNZOP4azjG4wDQYJKoZIhvcNAQEL
BQAwgaExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJTQzEVMBMGA1UEBwwMRGVmYXVs
dCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMRAwDgYDVQQLDAdU
ZXN0IENBMRowGAYDVQQDDBF3d3cuZXhhbXBsZWNhLmNvbTEiMCAGCSqGSIb3DQEJ
ARYTZXhhbXBsZUBleGFtcGxlLmNvbTAeFw0yNDAxMTAxOTAwMDRaFw0zNDAxMDcx
OTAwMDRaMHwxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTELMAkGA1UECAwCU0Mx
CzAJBgNVBAYTAlVTMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlQGV4YW1wbGUuY29t
MRAwDgYDVQQKDAdFeGFtcGxlMRAwDgYDVQQLDAdFeGFtcGxlMIGfMA0GCSqGSIb3
DQEBAQUAA4GNADCBiQKBgQDNAbvvqB1dcHKYVkWzC1H7fHw+5zxvecbO1Hiz6YRW
bkoSIYXQEDKb3LBXoPgYPT1grr942ZY5pNOjC77li38I2H6Pav1fqjmVX01Rx22i
DuUU1yTAtjZ/gAhdJBwZjXG7YTjoBfC/OeGvz/LY5tYj0fvrx55HsdDR+5cqLFXP
7wIDAQABo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBSYTeaq+a2V/7QWJh/gH2tE
GXln7jAfBgNVHSMEGDAWgBRQlTo+l7rGlVRX5myTzXIHBN587jANBgkqhkiG9w0B
AQsFAAOBgQCvvO7Gp9zfrKa5LRrfPQuz82Q47UDSeZTmn1Hi6RJxpbgmSggsXV5W
ibm7ToWdUrcOsmj0gwZO08jP5G5gy52kShogSy8Je7Qj7Jf4OOdG2pCMe1BEYdyS
8W1kEoEBL8JhHt1ftjW2U3rPhxbtOLZ0gnzLf30T9GfgAB1nwadcwA==
-----END CERTIFICATE-----`

	testCertPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDNAbvvqB1dcHKYVkWzC1H7fHw+5zxvecbO1Hiz6YRWbkoSIYXQ
EDKb3LBXoPgYPT1grr942ZY5pNOjC77li38I2H6Pav1fqjmVX01Rx22iDuUU1yTA
tjZ/gAhdJBwZjXG7YTjoBfC/OeGvz/LY5tYj0fvrx55HsdDR+5cqLFXP7wIDAQAB
AoGAfE7P4Zsj6zOzGPI/Izj7Bi5OvGnEeKfzyBiH9Dflue74VRQkqqwXs/DWsNv3
c+M2Y3iyu5ncgKmUduo5X8D9To2ymPRLGuCdfZTxnBMpIDKSJ0FTwVPkr6cYyyBk
5VCbc470pQPxTAAtl2eaO1sIrzR4PcgwqrSOjwBQQocsGAECQQD8QOra/mZmxPbt
bRh8U5lhgZmirImk5RY3QMPI/1/f4k+fyjkU5FRq/yqSyin75aSAXg8IupAFRgyZ
W7BT6zwBAkEA0A0ugAGorpCbuTa25SsIOMxkEzCiKYvh0O+GfGkzWG4lkSeJqGME
keuJGlXrZNKNoCYLluAKLPmnd72X2yTL7wJARM0kAXUP0wn324w8+HQIyqqBj/gF
Vt9Q7uMQQ3s72CGu3ANZDFS2nbRZFU5koxrggk6lRRk1fOq9NvrmHg10AQJABOea
pgfj+yGLmkUw8JwgGH6xCUbHO+WBUFSlPf+Y50fJeO+OrjqPXAVKeSV3ZCwWjKT4
9viXJNJJ4WfF0bO/XwJAOMB1wQnEOSZ4v+laMwNtMq6hre5K8woqteXICoGcIWe8
u3YLAbyW/lHhOCiZu2iAI8AbmXem9lW6Tr7p/97s0w==
-----END RSA PRIVATE KEY-----`

	// openssl req -newkey rsa:1024 -nodes -keyout testExpiredCert.key -out testExpiredCert.csr -subj '/CN=www.example.com/ST=SC/C=US/emailAddress=example@example.com/O=Example/OU=Example'
	// faketime 'last year 5pm' /bin/bash -c 'openssl x509 -req -days 1 -sha256 -in testExpiredCert.csr -CA exampleca.crt -CAcreateserial -CAkey testCACertificate.key -extensions ext -extfile <(echo $"[ext]\nbasicConstraints = CA:FALSE") -out testExpiredCert.crt'
	//
	// Signature Algorithm: sha256WithRSAEncryption
	// Issuer: C = US, ST = SC, L = Default City, O = Default Company Ltd, OU = Test CA, CN = www.exampleca.com, emailAddress = example@example.com
	// Validity
	//    Not Before: Jan 16 22:00:00 2023 GMT
	//    Not After : Jan 17 22:00:00 2023 GMT
	// Subject: CN = www.example.com, ST = SC, C = US, emailAddress = example@example.com, O = Example, OU = Example
	// Key = testExpiredCertKey
	// CA = testCACertificate
	testExpiredCert = `-----BEGIN CERTIFICATE-----
MIICoDCCAgkCFE1r/2f+5TpHQhC7pZzWTj+Gs4yGMA0GCSqGSIb3DQEBCwUAMIGh
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCU0MxFTATBgNVBAcMDERlZmF1bHQgQ2l0
eTEcMBoGA1UECgwTRGVmYXVsdCBDb21wYW55IEx0ZDEQMA4GA1UECwwHVGVzdCBD
QTEaMBgGA1UEAwwRd3d3LmV4YW1wbGVjYS5jb20xIjAgBgkqhkiG9w0BCQEWE2V4
YW1wbGVAZXhhbXBsZS5jb20wHhcNMjMwMTE2MjIwMDAwWhcNMjMwMTE3MjIwMDAw
WjB8MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xCzAJBgNVBAgMAlNDMQswCQYD
VQQGEwJVUzEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbTEQMA4G
A1UECgwHRXhhbXBsZTEQMA4GA1UECwwHRXhhbXBsZTCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEA9K4gDr8ZKZJDokTeK79guq/0rnTSJiZhZ4I9a6GvYkqqQBxT
xND1E7RyvrkIIxq/BbzpmoAny+EbKiF+GuG0e6SVI9dYjs9eRsYTVki/gsbWKTPZ
bNvZg+r5wI9CpwHuVmT6YOxTSxcXHAquuohACcgUWaptPbBaEjna8v3Ue4MCAwEA
ATANBgkqhkiG9w0BAQsFAAOBgQBtfVNlfP0sp2zE9KvwVqV2bZVjd2jTqXyg2qmK
CWrwe70nXXgvhG/DT2kHU0wlecBmrf3NTv77NQCtmQNih8Wenxz9EYk2K69IcFS6
en17RQP5sdHRtiCRx0yc/InAQXYXoQiyETFA0/YRhh6ss7pgEdvFZTPz1cFFsFbv
074olw==
-----END CERTIFICATE-----`

	testExpiredCertKey = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPSuIA6/GSmSQ6JE
3iu/YLqv9K500iYmYWeCPWuhr2JKqkAcU8TQ9RO0cr65CCMavwW86ZqAJ8vhGyoh
fhrhtHuklSPXWI7PXkbGE1ZIv4LG1ikz2Wzb2YPq+cCPQqcB7lZk+mDsU0sXFxwK
rrqIQAnIFFmqbT2wWhI52vL91HuDAgMBAAECgYAhcrhBK9CFxU/nm+B/PH89phYd
zyx3OKHyI3TABO9T0X8qmnS9IA+QrQdOmT7Khbp9T1Dj5QcLsO8kuEVj6VzhkbVy
PIvxEQiL/ngJJu8V7bT0NK8A+7kR8YnKU/K+iKBJ+0shM24IBy40NGddSQ48GBzc
ArIhBPycR4eTi9PpYQJBAPvi9hINkSIGG2QHWhXXNzFN6lxD/frHzU7zqNJKfIEG
aXCEeiih8Dqfl4SeuWNfwqxgp+HtsuHz7AuLr/XOMBMCQQD4rQlz2aV/HymNw9+n
V5jpt2VmTtWyziwl52hMJ51c6DGpBTezSMmNn3Q4AkwrQw5SDVusCK4QY21MkwKV
g1TRAkAOY8jq/xtrdi3aaREcbk8Y4fqhisDXstJn0EO0v8ydEmCzrN3NtHKk5rkh
OnAc3Tuh3WO55HpzrhuuDSzgPgdBAkEAn1UHdHIkhtHppwq0l50Zvc4jKy0h4UIW
qWaevgS34BpqDzjnmnjto09igKyAL0v0tgAXF6AsHxYFpwWepzuRsQJBAJzCLvnL
336G+BzgA2fOMWJibkI6e0aTkur+AZ0aa1dCmLDHOYaq42eLCQFSwCWk3ZIe6+7/
+jCpmLpAmN/zKSo=
-----END PRIVATE KEY-----`

	testCertificate = `-----BEGIN CERTIFICATE-----
MIICwjCCAiugAwIBAgIBATANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExETAPBgNVBAoMCFNlY3VyaXR5MRswGQYDVQQLDBJPcGVuU2hp
ZnQzIHRlc3QgQ0ExFzAVBgNVBAMMDmhlYWRlci50ZXN0IENBMB4XDTE2MDMxMjA0
MjEwM1oXDTM2MDMxMjA0MjEwM1owWDEUMBIGA1UEAwwLaGVhZGVyLnRlc3QxCzAJ
BgNVBAgMAkNBMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU2VjdXJpdHkxEzARBgNV
BAsMCk9wZW5TaGlmdDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0
XEAzUMflZy8zluwzqMKnu8jYK3yUoEGLN0Bw0A/7ydno1g0E92ee8M9p59TCCWA6
nKnt1DEK5285xAKs9AveutSYiDkpf2px59GvCVx2ecfFBTECWHMAJ/6Y7pqlWOt2
hvPx5rP+jVeNLAfK9d+f57FGvWXrQAcBnFTegS6J910kbvDgNP4Nerj6RPAx2UOq
6URqA4j7qZs63nReeu/1t//BQHNokKddfxw2ZXcL/5itgpPug16thp+ugGVdjcFs
aasLJOjErUS0D+7bot98FL0TSpxWqwtCF117bSLY7UczZFNAZAOnZBFmSZBxcJJa
TZzkda0Oiqo0J3GPcZ+rAgMBAAGjDTALMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL
BQADgYEACkdKRUm9ERjgbe6w0fw4VY1s5XC9qR1m5AwLMVVwKxHJVG2zMzeDTHyg
3cjxmfZdFU9yxmNUCh3mRsi2+qjEoFfGRyMwMMx7cduYhsFY3KA+Fl4vBRXAuPLR
eCI4ErCPi+Y08vOto9VVXg2f4YFQYLq1X6TiXD5RpQAN0t8AYk4=
-----END CERTIFICATE-----`

	testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA9FxAM1DH5WcvM5bsM6jCp7vI2Ct8lKBBizdAcNAP+8nZ6NYN
BPdnnvDPaefUwglgOpyp7dQxCudvOcQCrPQL3rrUmIg5KX9qcefRrwlcdnnHxQUx
AlhzACf+mO6apVjrdobz8eaz/o1XjSwHyvXfn+exRr1l60AHAZxU3oEuifddJG7w
4DT+DXq4+kTwMdlDqulEagOI+6mbOt50Xnrv9bf/wUBzaJCnXX8cNmV3C/+YrYKT
7oNerYafroBlXY3BbGmrCyToxK1EtA/u26LffBS9E0qcVqsLQhdde20i2O1HM2RT
QGQDp2QRZkmQcXCSWk2c5HWtDoqqNCdxj3GfqwIDAQABAoIBAEfl+NHge+CIur+w
MXGFvziBLThFm1NTz9U5fZFz9q/8FUzH5m7GqMuASVb86oHpJlI4lFsw6vktXXGe
tbbT28Y+LJ1wv3jxT42SSwT4eSc278uNmnz5L2UlX2j6E7CA+E8YqCBN5DoKtm8I
PIbAT3sKPgP1aE6OuUEFEYeidOIMvjco2aQH0338sl6cObkQFEgnWf2ncun3KGnb
s+dMO5EdYLo0rOdDXY88sElfqiNYYl/FRu9O3OfqHvScA5uo9FlIhukcrRkbjFcq
j/7k4tt0iLs9B2j+4ihBWYo5eRFIde4Izj6a6ArEk0ShEUvwlZBuGMM/vs+jvbDK
l3+0NpECgYEA/+qxwvOGjmlYNKFK/rzxd51EnfCISnV+tb17pNyRmlGToi1/LmmV
+jcJfcwlf2o8mTFn3xAdD3fSaHF7t8Li7xDwH2S+sSuFE/8bhgHUvw1S7oILMYyO
hO6sWG+JocMhr8IejaAnQxav9VvP01YDfw/XBB0O1EIuzzr2KHq+AGMCgYEA9HCY
JGTcv7lfs3kcCAkDtjl8NbjNRMxRErG0dfYS+6OSaXOOMg1TsaSNEgjOGyUX+yQ4
4vtKcLwHk7+qz3ZPbhS6m7theZG9jUwMrQRGyCE7z3JUy8vmV/N+HP0V+boT+4KM
Tai3+I3hf9+QMHYx/Z/VA0K6f27LwP+kEL9C8hkCgYEAoiHeXNRL+w1ihHVrPdgW
YuGQBz/MGOA3VoylON1Eoa/tCGIqoQzjp5IWwUwEtaRon+VdGUTsJFCVTPYYm2Ms
wqjIeBsrdLNNrE2C8nNWhXO7hr98t/eEk1NifOStHX6yaNdi4/cC6M4GzDtOf2WO
8YDniAOg0Xjcjw2bxil9FmECgYBuUeq4cjUW6okArSYzki30rhka/d7WsAffEgjK
PFbw7zADG74PZOhjAksQ2px6r9EU7ZInDxbXrmUVD6n9m/3ZRs25v2YMwfP0s1/9
LjLr2+PsikMu/0VkaGaAmtCyNoMSPicoXX86VH5zgejHlnCVcO9oW1NkdBLNdhML
4+ZI8QKBgQDb+SH7i50Yu3adwvPkDSp3ACCzPoHXno79a7Y5S2JzpFtNq+cNLWEb
HP8gHJSZnaGrLKmjwNeQNsARYajKmDKO5HJ9g5H5Hae8enOb2yie541dneDT8rID
4054dMQJnijd8620yf8wiNy05ZPOQQ0JvA/rW3WWZc5PGm8c2PsVjg==
-----END RSA PRIVATE KEY-----`

	testCACertificate = `-----BEGIN CERTIFICATE-----
MIIClDCCAf2gAwIBAgIJAPU57OGhuqJtMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UECgwIU2VjdXJpdHkxGzAZBgNVBAsM
Ek9wZW5TaGlmdDMgdGVzdCBDQTEXMBUGA1UEAwwOaGVhZGVyLnRlc3QgQ0EwHhcN
MTYwMzEyMDQyMTAzWhcNMzYwMzEyMDQyMTAzWjBjMQswCQYDVQQGEwJVUzELMAkG
A1UECAwCQ0ExETAPBgNVBAoMCFNlY3VyaXR5MRswGQYDVQQLDBJPcGVuU2hpZnQz
IHRlc3QgQ0ExFzAVBgNVBAMMDmhlYWRlci50ZXN0IENBMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCsdVIJ6GSrkFdE9LzsMItYGE4q3qqSqIbs/uwMoVsMT+33
pLeyzeecPuoQsdO6SEuqhUM1ivUN4GyXIR1+aW2baMwMXpjX9VIJu5d4FqtGi6SD
RfV+tbERWwifPJlN+ryuvqbbDxrjQeXhemeo7yrJdgJ1oyDmoM5pTiSUUmltvQID
AQABo1AwTjAdBgNVHQ4EFgQUOVuieqGfp2wnKo7lX2fQt+Yk1C4wHwYDVR0jBBgw
FoAUOVuieqGfp2wnKo7lX2fQt+Yk1C4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOBgQA8VhmNeicRnKgXInVyYZDjL0P4WRbKJY7DkJxRMRWxikbEVHdySki6
jegpqgJqYbzU6EiuTS2sl2bAjIK9nGUtTDt1PJIC1Evn5Q6v5ylNflpv6GxtUbCt
bGvtpjWA4r9WASIDPFsxk/cDEEEO6iPxgMOf5MdpQC2y2MU0rzF/Gg==
-----END CERTIFICATE-----`

	testDestinationCACertificate = testCACertificate

	// openssl req -x509 -sha1 -newkey rsa:1024 -days 3650 -keyout exampleca.key -out exampleca.crt -addext "keyUsage=cRLSign, digitalSignature, keyCertSign" -addext "extendedKeyUsage=serverAuth, clientAuth" -nodes -subj '/C=US/ST=SC/L=Default City/O=Default Company Ltd/OU=Test CA/CN=www.exampleca.com/emailAddress=example@example.com'
	// openssl req -newkey rsa:1024 -nodes -keyout testCertificateRsaSha1.key -out testCertificateRsaSha1.csr -subj '/CN=www.example.com/ST=SC/C=US/emailAddress=example@example.com/O=Example/OU=Example'
	// openssl x509 -req -days 3650 -sha1 -in testCertificateRsaSha1.csr -CA exampleca.crt -CAcreateserial -CAkey exampleca.key -extensions ext -extfile <(echo $'[ext]\nbasicConstraints = CA:FALSE') -out testCertificateRsaSha1.crt
	//
	// Signature Algorithm: sha1WithRSAEncryption
	// Issuer: C = US, ST = SC, L = Default City, O = Default Company Ltd, OU = Test CA, CN = www.exampleca.com, emailAddress = example@example.com
	// Validity
	//    Not Before: Jan 10 19:56:08 2024 GMT
	//    Not After : Jan  7 19:56:08 2034 GMT
	// Subject: CN = www.example.com, ST = SC, C = US, emailAddress = example@example.com, O = Example, OU = Example
	// Key = testCertificateRsaSha1Key
	testCertificateRsaSha1 = `-----BEGIN CERTIFICATE-----
MIIC9DCCAl2gAwIBAgIUTWv/Z/7lOkdCELulnNZOP4azjHowDQYJKoZIhvcNAQEF
BQAwgaExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJTQzEVMBMGA1UEBwwMRGVmYXVs
dCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMRAwDgYDVQQLDAdU
ZXN0IENBMRowGAYDVQQDDBF3d3cuZXhhbXBsZWNhLmNvbTEiMCAGCSqGSIb3DQEJ
ARYTZXhhbXBsZUBleGFtcGxlLmNvbTAeFw0yNDAxMTAxOTU2MDhaFw0zNDAxMDcx
OTU2MDhaMHwxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTELMAkGA1UECAwCU0Mx
CzAJBgNVBAYTAlVTMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlQGV4YW1wbGUuY29t
MRAwDgYDVQQKDAdFeGFtcGxlMRAwDgYDVQQLDAdFeGFtcGxlMIGfMA0GCSqGSIb3
DQEBAQUAA4GNADCBiQKBgQC4hsxewdQOk5goI9bdkR1urJnbu7TeZdDtPz0Mi976
1guAxNPQO98t0X/Bhs7toZz/zIG4vQZfXaV2IU1ry7pQ64I8bTPXQ/Kpt8zW3zng
dPeIJqVujKPybIL/teHJ1Bw4c4x1ZMpAGoZ6s750tQy1zP7WRqStJv2G9l3OQLFu
AQIDAQABo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBS6uwvwYLV5u4TX9ZFMBpQe
hW4YKjAfBgNVHSMEGDAWgBRQlTo+l7rGlVRX5myTzXIHBN587jANBgkqhkiG9w0B
AQUFAAOBgQB+1bS0s6SpuCuMFFMpeBcE7WX//AGU/ZcRfO60ithV6NQ9OnN3djfS
H+ZeW3QEaQVMM0PIOuMO22/9AN6UVs8IxSuSkrfBOQ+PY/3169b6rpGl44/ZTx6B
O+c5wkkhnmy4+T6KnjQE5aO1VKBp3Ocl8PyIBqLLV52pZWUuytGlqA==
-----END CERTIFICATE-----
`
	testCertificateRsaSha1Key = `
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALiGzF7B1A6TmCgj
1t2RHW6smdu7tN5l0O0/PQyL3vrWC4DE09A73y3Rf8GGzu2hnP/Mgbi9Bl9dpXYh
TWvLulDrgjxtM9dD8qm3zNbfOeB094gmpW6Mo/Jsgv+14cnUHDhzjHVkykAahnqz
vnS1DLXM/tZGpK0m/Yb2Xc5AsW4BAgMBAAECgYAWaNBzBYkSSBxna4rRl6kCYtXA
mLgrdiP8W/y3BFmNDueQuNacaFj/QH0KbKu+sizV5+ktHU+jz0Sj5wF3AOPccRtJ
QcGxr66f1uVPeBQfO27ac8b5UYwIFCu4gJ9IQp86INARuO4U5UR2o7sJ8rUpmf2M
p2JUQwKXjO0qDyDcQQJBAODWqTkdr0Av2vAOZe6SOfmr+u/2shAWPTg8uc1Y08Ng
1Fh0o7vqkOQ6Amtw4o5lE0RE0LlPSnxhpl28sT0gwUkCQQDSGdtIk77rh+WqNjYZ
GWhKBA2H8w0jo37Wz1aGyv/Yt6LC/LgOdOcadu4xSIgG+Al9JHdzLx7iWvNdIjD6
l/75AkEA1szdwL5WVnkhrmPjCAhVMO0YALbrqKjGdfq1+7OYJDlWxOcyIe5X3GJ7
O1AOccGopXkk+1UAMVJNUZJata6cWQJBAIEvhubsecNHL09mwALU3YxNS6ihKR4V
xML+gBynq4Ms/vZYADBbb1KVeEZza7ilQOhiyNPZUGssM2G7yVP8q7kCQHFCAgmO
redbrtiWNunEy1hVHOJD6ALriPz2i1W51NMbrPV2kOy9GpV/p3oby3GmXHs+Zlo6
bBbOLhI7o+VlGaM=
-----END PRIVATE KEY-----`
)

// TestRouter provides an implementation of the plugin's router interface suitable for unit testing.
type TestRouter struct {
	State        map[ServiceAliasConfigKey]ServiceAliasConfig
	ServiceUnits map[ServiceUnitKey]ServiceUnit
}

// NewTestRouter creates a new TestRouter and registers the initial state.
func newTestRouter(state map[ServiceAliasConfigKey]ServiceAliasConfig) *TestRouter {
	return &TestRouter{
		State:        state,
		ServiceUnits: make(map[ServiceUnitKey]ServiceUnit),
	}
}

// CreateServiceUnit creates an empty service unit identified by id
func (r *TestRouter) CreateServiceUnit(id ServiceUnitKey) {
	su := ServiceUnit{
		Name:          string(id),
		EndpointTable: []Endpoint{},
	}

	r.ServiceUnits[id] = su
}

// FindServiceUnit finds the service unit in the state
func (r *TestRouter) FindServiceUnit(id ServiceUnitKey) (v ServiceUnit, ok bool) {
	v, ok = r.ServiceUnits[id]
	return
}

// AddEndpoints adds the endpoints to the service unit identified by id
func (r *TestRouter) AddEndpoints(id ServiceUnitKey, endpoints []Endpoint) {
	su, _ := r.FindServiceUnit(id)

	// simulate the logic that compares endpoints
	if reflect.DeepEqual(su.EndpointTable, endpoints) {
		return
	}
	su.EndpointTable = endpoints
	r.ServiceUnits[id] = su
}

// DeleteEndpoints removes all endpoints from the service unit
func (r *TestRouter) DeleteEndpoints(id ServiceUnitKey) {
	if su, ok := r.FindServiceUnit(id); !ok {
		return
	} else {
		su.EndpointTable = []Endpoint{}
		r.ServiceUnits[id] = su
	}
}

func (r *TestRouter) calculateServiceWeights(serviceUnits map[ServiceUnitKey]int32) map[ServiceUnitKey]int32 {
	var serviceWeights = make(map[ServiceUnitKey]int32)
	for key := range serviceUnits {
		serviceWeights[key] = serviceUnits[key]
	}
	return serviceWeights
}

// AddRoute adds a ServiceAliasConfig and associated ServiceUnits for the route
func (r *TestRouter) AddRoute(route *routev1.Route) {
	routeKey := getKey(route)

	config := ServiceAliasConfig{
		Host:         route.Spec.Host,
		Path:         route.Spec.Path,
		ServiceUnits: getServiceUnits(route),
	}
	config.ServiceUnitNames = r.calculateServiceWeights(config.ServiceUnits)

	for key := range config.ServiceUnits {
		r.CreateServiceUnit(key)
	}

	r.State[routeKey] = config
}

// RemoveRoute removes the service alias config for Route
func (r *TestRouter) RemoveRoute(route *routev1.Route) {
	routeKey := getKey(route)
	_, ok := r.State[routeKey]
	if !ok {
		return
	} else {
		delete(r.State, routeKey)
	}
}

func (r *TestRouter) HasRoute(route *routev1.Route) bool {
	// Not used
	return false
}

func (r *TestRouter) SyncedAtLeastOnce() bool {
	// Not used
	return false
}

func (r *TestRouter) FilterNamespaces(namespaces sets.String) {
	if len(namespaces) == 0 {
		r.State = make(map[ServiceAliasConfigKey]ServiceAliasConfig)
		r.ServiceUnits = make(map[ServiceUnitKey]ServiceUnit)
	}
	for k := range r.ServiceUnits {
		// TODO: the id of a service unit should be defined inside this class, not passed in from the outside
		//   remove the leak of the abstraction when we refactor this code
		ns, _ := getPartsFromEndpointsKey(k)
		if namespaces.Has(ns) {
			continue
		}
		delete(r.ServiceUnits, k)
	}

	for k := range r.State {
		ns, _ := getPartsFromRouteKey(k)
		if namespaces.Has(ns) {
			continue
		}
		delete(r.State, k)
	}
}

// getKey create an identifier for the route consisting of host-path
func getKey(route *routev1.Route) ServiceAliasConfigKey {
	return routeKeyFromParts(route.Spec.Host, route.Spec.Path)
}

func (r *TestRouter) Commit() {
	// No op
}

// TestHandleEndpoints test endpoint watch events
func TestHandleEndpoints(t *testing.T) {
	testCases := []struct {
		name                string          //human readable name for test case
		eventType           watch.EventType //type to be passed to the HandleEndpoints method
		endpoints           *kapi.Endpoints //endpoints to be passed to the HandleEndpoints method
		expectedServiceUnit *ServiceUnit    //service unit that will be compared against.
		excludeUDP          bool
	}{
		{
			name:      "Endpoint add",
			eventType: watch.Added,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test", //kapi.endpoints inherits the name of the service
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "1.1.1.1"}},
					Ports:     []kapi.EndpointPort{{Port: 345, Name: "port"}},
				}}, //not specifying a port to force the port 80 assumption
			},
			expectedServiceUnit: &ServiceUnit{
				Name: "foo/test", //service name from kapi.endpoints object
				EndpointTable: []Endpoint{
					{
						ID:   "ept:test:port:1.1.1.1:345",
						IP:   "1.1.1.1",
						Port: "345",
					},
				},
			},
		},
		{
			name:      "Endpoint mod",
			eventType: watch.Modified,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test",
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "2.2.2.2", TargetRef: &kapi.ObjectReference{Kind: "Pod", Name: "pod-1"}}},
					Ports:     []kapi.EndpointPort{{Port: 8080, Name: "port"}},
				}},
			},
			expectedServiceUnit: &ServiceUnit{
				Name: "foo/test",
				EndpointTable: []Endpoint{
					{
						ID:   "pod:pod-1:test:port:2.2.2.2:8080",
						IP:   "2.2.2.2",
						Port: "8080",
					},
				},
			},
		},
		{
			name:      "Endpoint delete",
			eventType: watch.Deleted,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test",
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "3.3.3.3"}},
					Ports:     []kapi.EndpointPort{{Port: 0}},
				}},
			},
			expectedServiceUnit: &ServiceUnit{
				Name:          "foo/test",
				EndpointTable: []Endpoint{},
			},
		},
	}

	router := newTestRouter(make(map[ServiceAliasConfigKey]ServiceAliasConfig))
	templatePlugin := newDefaultTemplatePlugin(router, true, nil)
	// TODO: move tests that rely on unique hosts to pkg/router/controller and remove them from
	// here
	plugin := controller.NewUniqueHost(templatePlugin, false, controller.LogRejections)

	for _, tc := range testCases {
		plugin.HandleEndpoints(tc.eventType, tc.endpoints)

		su, ok := router.FindServiceUnit(ServiceUnitKey(tc.expectedServiceUnit.Name))

		if !ok {
			t.Errorf("TestHandleEndpoints test case %s failed.  Couldn't find expected service unit with name %s", tc.name, tc.expectedServiceUnit.Name)
		} else {
			if len(su.EndpointTable) != len(tc.expectedServiceUnit.EndpointTable) {
				t.Errorf("TestHandleEndpoints test case %s failed. endpoints: %d expected %d", tc.name, len(su.EndpointTable), len(tc.expectedServiceUnit.EndpointTable))
			}
			for expectedKey, expectedEp := range tc.expectedServiceUnit.EndpointTable {
				actualEp := su.EndpointTable[expectedKey]

				if expectedEp.ID != actualEp.ID || expectedEp.IP != actualEp.IP || expectedEp.Port != actualEp.Port {
					t.Errorf("TestHandleEndpoints test case %s failed.  Expected endpoint didn't match actual endpoint %v : %v", tc.name, expectedEp, actualEp)
				}
			}
		}
	}
}

// TestHandleTCPEndpoints test endpoint watch events with UDP excluded
func TestHandleTCPEndpoints(t *testing.T) {
	testCases := []struct {
		name                string          //human readable name for test case
		eventType           watch.EventType //type to be passed to the HandleEndpoints method
		endpoints           *kapi.Endpoints //endpoints to be passed to the HandleEndpoints method
		expectedServiceUnit *ServiceUnit    //service unit that will be compared against.
	}{
		{
			name:      "Endpoint add",
			eventType: watch.Added,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test", //kapi.endpoints inherits the name of the service
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "1.1.1.1", TargetRef: &kapi.ObjectReference{Kind: "Pod", Name: "pod-1"}}},
					Ports: []kapi.EndpointPort{
						{Port: 345, Name: "tcp"},
						{Port: 346, Protocol: kapi.ProtocolUDP, Name: "udp"},
					},
				}}, //not specifying a port to force the port 80 assumption
			},
			expectedServiceUnit: &ServiceUnit{
				Name: "foo/test", //service name from kapi.endpoints object
				EndpointTable: []Endpoint{
					{
						ID:   "pod:pod-1:test:tcp:1.1.1.1:345",
						IP:   "1.1.1.1",
						Port: "345",
					},
				},
			},
		},
		{
			name:      "Endpoint mod",
			eventType: watch.Modified,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test",
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "2.2.2.2"}},
					Ports: []kapi.EndpointPort{
						{Port: 8080, Name: "tcp"},
						{Port: 8081, Protocol: kapi.ProtocolUDP, Name: "udp"},
					},
				}},
			},
			expectedServiceUnit: &ServiceUnit{
				Name: "foo/test",
				EndpointTable: []Endpoint{
					{
						ID:   "ept:test:tcp:2.2.2.2:8080",
						IP:   "2.2.2.2",
						Port: "8080",
					},
				},
			},
		},
		{
			name:      "Endpoint delete",
			eventType: watch.Deleted,
			endpoints: &kapi.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "test",
				},
				Subsets: []kapi.EndpointSubset{{
					Addresses: []kapi.EndpointAddress{{IP: "3.3.3.3"}},
					Ports:     []kapi.EndpointPort{{Port: 0}},
				}},
			},
			expectedServiceUnit: &ServiceUnit{
				Name:          "foo/test",
				EndpointTable: []Endpoint{},
			},
		},
	}

	router := newTestRouter(make(map[ServiceAliasConfigKey]ServiceAliasConfig))
	templatePlugin := newDefaultTemplatePlugin(router, false, nil)
	// TODO: move tests that rely on unique hosts to pkg/router/controller and remove them from
	// here
	plugin := controller.NewUniqueHost(templatePlugin, false, controller.LogRejections)

	for _, tc := range testCases {
		plugin.HandleEndpoints(tc.eventType, tc.endpoints)

		su, ok := router.FindServiceUnit(ServiceUnitKey(tc.expectedServiceUnit.Name))

		if !ok {
			t.Errorf("TestHandleEndpoints test case %s failed.  Couldn't find expected service unit with name %s", tc.name, tc.expectedServiceUnit.Name)
		} else {
			for expectedKey, expectedEp := range tc.expectedServiceUnit.EndpointTable {
				actualEp := su.EndpointTable[expectedKey]

				if expectedEp.ID != actualEp.ID || expectedEp.IP != actualEp.IP || expectedEp.Port != actualEp.Port {
					t.Errorf("TestHandleEndpoints test case %s failed.  Expected endpoint didn't match actual endpoint %v : %v", tc.name, expectedEp, actualEp)
				}
			}
		}
	}
}

type status struct {
	route   *routev1.Route
	reason  string
	message string
}

type fakeStatusRecorder struct {
	rejections []status
	deprecated []status
}

func (r *fakeStatusRecorder) RecordRouteRejection(route *routev1.Route, reason, message string) {
	r.rejections = append(r.rejections, status{route: route, reason: reason, message: message})
}
func (r *fakeStatusRecorder) RecordRouteDeprecated(route *routev1.Route, reason, message string) {
	r.deprecated = append(r.deprecated, status{route: route, reason: reason, message: message})
}
func (r *fakeStatusRecorder) RecordRouteNotDeprecated(route *routev1.Route) {
	var deprecated []status
	for _, rejection := range r.deprecated {
		if rejection.route.UID != route.UID {
			deprecated = append(deprecated, rejection)
		}
	}
	r.deprecated = deprecated
}

func (r *fakeStatusRecorder) isDeprecated(route *routev1.Route) bool {
	for _, r := range r.deprecated {
		if r.route.UID == route.UID {
			return true
		}
	}
	return false
}

// TestHandleRoute test route watch events
func TestHandleRoute(t *testing.T) {
	rejections := &fakeStatusRecorder{}
	router := newTestRouter(make(map[ServiceAliasConfigKey]ServiceAliasConfig))
	templatePlugin := newDefaultTemplatePlugin(router, true, nil)
	// TODO: move tests that rely on unique hosts to pkg/router/controller and remove them from
	// here
	plugin := controller.NewUniqueHost(templatePlugin, false, rejections)

	uidCount := 0
	nextUID := func() types.UID {
		uidCount++
		return types.UID(fmt.Sprintf("%03d", uidCount))
	}
	original := metav1.Time{Time: time.Now()}

	//add
	fooTest1 := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: original,
			Namespace:         "foo",
			Name:              "test",
			UID:               nextUID(),
		},
		Spec: routev1.RouteSpec{
			Host: "www.example.com",
			To: routev1.RouteTargetReference{
				Name:   "TestService",
				Weight: new(int32),
			},
		},
	}
	serviceUnitKey := endpointsKeyFromParts(fooTest1.Namespace, fooTest1.Spec.To.Name)

	plugin.HandleRoute(watch.Added, fooTest1)

	_, ok := router.FindServiceUnit(serviceUnitKey)

	if !ok {
		t.Errorf("TestHandleRoute was unable to find the service unit %s after HandleRoute was called", fooTest1.Spec.To.Name)
	} else {
		serviceAliasCfg, ok := router.State[getKey(fooTest1)]

		if !ok {
			t.Errorf("TestHandleRoute expected route key %s", getKey(fooTest1))
		} else {
			if serviceAliasCfg.Host != fooTest1.Spec.Host || serviceAliasCfg.Path != fooTest1.Spec.Path {
				t.Errorf("Expected route did not match service alias config %v : %v", fooTest1, serviceAliasCfg)
			}
		}
	}

	if len(rejections.rejections) > 0 {
		t.Fatalf("did not expect a recorded status: %#v", rejections)
	}

	// attempt to add a second route with a newer time, verify it is ignored
	fooDupe2 := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: metav1.Time{Time: original.Add(time.Hour)},
			Namespace:         "foo",
			Name:              "dupe",
			UID:               nextUID(),
		},
		Spec: routev1.RouteSpec{
			Host: "www.example.com",
			To: routev1.RouteTargetReference{
				Name:   "TestService2",
				Weight: new(int32),
			},
		},
	}
	if err := plugin.HandleRoute(watch.Added, fooDupe2); err != nil {
		t.Fatal("unexpected error")
	}

	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService2")); ok {
		t.Fatalf("unexpected second unit: %#v", router)
	}
	if r, ok := plugin.RoutesForHost("www.example.com"); !ok || r[0].Name != "test" {
		t.Fatalf("unexpected claimed routes: %#v", r)
	}
	if len(rejections.rejections) != 1 ||
		rejections.rejections[0].route.Name != "dupe" ||
		rejections.rejections[0].reason != "HostAlreadyClaimed" ||
		rejections.rejections[0].message != "route test already exposes www.example.com and is older" {
		t.Fatalf("did not record status: %#v", rejections)
	}
	rejections.rejections = nil

	// attempt to remove the second route that is not being used, verify it is ignored
	if err := plugin.HandleRoute(watch.Deleted, fooDupe2); err != nil {
		t.Fatal("unexpected error")
	}

	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService2")); ok {
		t.Fatalf("unexpected second unit: %#v", router)
	}
	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); !ok {
		t.Fatalf("unexpected first unit: %#v", router)
	}
	if r, ok := plugin.RoutesForHost("www.example.com"); !ok || r[0].Name != "test" {
		t.Fatalf("unexpected claimed routes: %#v", r)
	}
	if len(rejections.rejections) != 0 {
		t.Fatalf("did not record status: %#v", rejections)
	}
	rejections.rejections = nil

	// add a third route with an older time, verify it takes effect
	copied := *fooDupe2
	fooDupe3 := &copied
	fooDupe3.UID = nextUID()
	fooDupe3.CreationTimestamp = metav1.Time{Time: original.Add(-time.Hour)}
	if err := plugin.HandleRoute(watch.Added, fooDupe3); err != nil {
		t.Fatal("unexpected error")
	}
	_, ok = router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService2"))
	if !ok {
		t.Fatalf("missing second unit: %#v", router)
	}
	if len(rejections.rejections) != 1 ||
		rejections.rejections[0].route.Name != "test" ||
		rejections.rejections[0].reason != "HostAlreadyClaimed" ||
		rejections.rejections[0].message != "replaced by older route dupe" {
		t.Fatalf("did not record status: %#v", rejections)
	}
	rejections.rejections = nil

	//mod
	copied2 := *fooTest1
	fooTest1NewHost := &copied2
	fooTest1NewHost.Spec.Host = "www.example2.com"
	if err := plugin.HandleRoute(watch.Modified, fooTest1NewHost); err != nil {
		t.Fatal("unexpected error")
	}

	key := getKey(fooTest1NewHost)
	_, ok = router.FindServiceUnit(serviceUnitKey)
	if !ok {
		t.Errorf("TestHandleRoute was unable to find the service unit %s after HandleRoute was called", fooTest1NewHost.Spec.To.Name)
	} else {
		serviceAliasCfg, ok := router.State[key]
		if !ok {
			t.Errorf("TestHandleRoute expected route key %s", key)
		} else {
			if serviceAliasCfg.Host != fooTest1NewHost.Spec.Host || serviceAliasCfg.Path != fooTest1NewHost.Spec.Path {
				t.Errorf("Expected route did not match service alias config %v : %v", fooTest1NewHost, serviceAliasCfg)
			}
		}
	}
	if plugin.HostLen() != 2 {
		t.Fatalf("did not clear claimed route: %#v", plugin)
	}
	if len(rejections.rejections) != 0 {
		t.Fatalf("unexpected status: %#v", rejections)
	}

	plugin.HandleRoute(watch.Deleted, fooDupe3)

	if plugin.HostLen() != 1 {
		t.Fatalf("did not clear claimed route: %#v", plugin)
	}
	if len(rejections.rejections) != 0 {
		t.Fatalf("unexpected status: %#v", rejections)
	}

	//delete
	if err := plugin.HandleRoute(watch.Deleted, fooTest1NewHost); err != nil {
		t.Fatal("unexpected error")
	}
	_, ok = router.FindServiceUnit(serviceUnitKey)
	if !ok {
		t.Errorf("TestHandleRoute was unable to find the service unit %s after HandleRoute was called", fooTest1NewHost.Spec.To.Name)
	} else {

		_, ok := router.State[key]

		if ok {
			t.Errorf("TestHandleRoute did not expect route key %s", key)
		}
	}
	if plugin.HostLen() != 0 {
		t.Errorf("did not clear claimed route: %#v", plugin)
	}
	if len(rejections.rejections) != 0 {
		t.Fatalf("unexpected status: %#v", rejections)
	}
}

type fakePlugin struct {
	Route *routev1.Route
	Err   error
}

func (p *fakePlugin) HandleRoute(event watch.EventType, route *routev1.Route) error {
	p.Route = route
	return p.Err
}

func (p *fakePlugin) HandleEndpoints(watch.EventType, *kapi.Endpoints) error {
	return p.Err
}

func (p *fakePlugin) HandleNamespaces(namespaces sets.String) error {
	return p.Err
}

func (p *fakePlugin) HandleNode(watch.EventType, *kapi.Node) error {
	return p.Err
}

func (p *fakePlugin) Commit() error {
	return p.Err
}

// TestHandleRouteExtendedValidation test route watch events with extended route configuration validation.
func TestHandleRouteExtendedValidation(t *testing.T) {
	rejections := &fakeStatusRecorder{}
	fake := &fakePlugin{}
	plugin := controller.NewExtendedValidator(fake, rejections)

	original := metav1.Time{Time: time.Now()}

	//add
	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: original,
			Namespace:         "foo",
			Name:              "test",
		},
		Spec: routev1.RouteSpec{
			Host: "www.example.com",
			To: routev1.RouteTargetReference{
				Name:   "TestService",
				Weight: new(int32),
			},
		},
	}

	plugin.HandleRoute(watch.Added, route)
	if fake.Route != route {
		t.Fatalf("unexpected route: %#v", fake.Route)
	}

	if len(rejections.rejections) > 0 {
		t.Fatalf("did not expect a recorded status: %#v", rejections)
	}

	tests := []struct {
		name          string
		route         *routev1.Route
		errorExpected bool
	}{
		{
			name: "No TLS Termination",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.no.tls.test",
					TLS: &routev1.TLSConfig{
						Termination: "",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Passthrough termination OK",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.passthrough.test",
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationPassthrough,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Reencrypt termination OK with certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.example.com",

					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              testCertificate,
						Key:                      testPrivateKey,
						CACertificate:            testCACertificate,
						DestinationCACertificate: testDestinationCACertificate,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Reencrypt termination OK with bad config",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencypt.badconfig.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              "def",
						Key:                      "ghi",
						CACertificate:            "jkl",
						DestinationCACertificate: "abc",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Reencrypt termination OK without certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencypt.nocerts.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						DestinationCACertificate: testDestinationCACertificate,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Reencrypt termination bad config without certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencypt.badconfignocerts.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						DestinationCACertificate: "abc",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Reencrypt termination no dest cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencypt.nodestcert.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationReencrypt,
						Certificate:   testCertificate,
						Key:           testPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Edge termination OK with certs without host",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testCertificate,
						Key:           testPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Edge termination OK with certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testCertificate,
						Key:           testPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Edge termination bad config with certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.badconfig.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   "abc",
						Key:           "abc",
						CACertificate: "abc",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Edge termination mismatched key and cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.mismatchdkeyandcert.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testCertificate,
						Key:           testCertPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Edge termination unknown CA",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.unknownca.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testCAUnknownCertificate,
						Key:           testCertPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Edge termination expired cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.expiredcert.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testExpiredCert,
						Key:           testExpiredCertKey,
						CACertificate: testCACertificate,
					},
				},
			},
		},
		{
			name: "Edge termination expired cert key mismatch",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.expiredcertkeymismatch.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testCAUnknownCertificate,
						Key:           testPrivateKey,
						CACertificate: testCACertificate,
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Edge termination OK without certs",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.nocerts.test",
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationEdge,
					},
				},
			},
			errorExpected: false,
		},
		{
			name: "Edge termination, bad dest cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.baddestcert.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationEdge,
						DestinationCACertificate: "abc",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Passthrough termination, bad cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.passthrough.badcert.test",
					TLS:  &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, Certificate: "test"},
				},
			},
			errorExpected: true,
		},
		{
			name: "Passthrough termination, bad key",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.passthrough.badkey.test",
					TLS:  &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, Key: "test"},
				},
			},
			errorExpected: true,
		},
		{
			name: "Passthrough termination, bad ca cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.passthrough.badcacert.test",
					TLS:  &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, CACertificate: "test"},
				},
			},
			errorExpected: true,
		},
		{
			name: "Passthrough termination, bad dest ca cert",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.passthrough.baddestcacert.test",
					TLS:  &routev1.TLSConfig{Termination: routev1.TLSTerminationPassthrough, DestinationCACertificate: "test"},
				},
			},
			errorExpected: true,
		},
		{
			name: "Invalid termination type",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					TLS: &routev1.TLSConfig{
						Termination: "invalid",
					},
				},
			},
			errorExpected: true,
		},
		{
			name: "Double escaped newlines",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencrypt.doubleescapednewlines.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              "d\\nef",
						Key:                      "g\\nhi",
						CACertificate:            "j\\nkl",
						DestinationCACertificate: "j\\nkl",
					},
				},
			},
			errorExpected: true,
		},
	}

	uidCount := 0
	nextUID := func() types.UID {
		uidCount++
		return types.UID(fmt.Sprintf("%03d", uidCount))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.route.UID = nextUID()
			err := plugin.HandleRoute(watch.Added, tc.route)
			if tc.errorExpected && err == nil {
				t.Fatal("expected an error, got none")
			} else if !tc.errorExpected && err != nil {
				t.Fatalf("expected no errors, got %v", err)
			}
		})
	}
}

// TestHandleRouteDeprecationValidation test route watch events with route deprecation validation plugin.
func TestHandleRouteDeprecationValidation(t *testing.T) {
	rejections := &fakeStatusRecorder{}
	fake := &fakePlugin{}
	plugin := controller.NewDeprecationValidation(fake, rejections)

	original := metav1.Time{Time: time.Now()}

	//add
	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: original,
			Namespace:         "foo",
			Name:              "test",
		},
		Spec: routev1.RouteSpec{
			Host: "www.example.com",
			To: routev1.RouteTargetReference{
				Name:   "TestService",
				Weight: new(int32),
			},
		},
	}

	plugin.HandleRoute(watch.Added, route)
	if fake.Route != route {
		t.Fatalf("unexpected route: %#v", fake.Route)
	}

	if len(rejections.rejections) > 0 {
		t.Fatalf("did not expect a recorded status: %#v", rejections)
	}

	tests := []struct {
		name               string
		route              *routev1.Route
		deprecatedExpected bool
	}{
		{
			name: "route with no cert should not be deprecated",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.normal.test",
				},
			},
		},
		{
			name: "route with SHA256 cert should not be deprecated",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.example.com",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              testCertificate,
						Key:                      testPrivateKey,
						CACertificate:            testCACertificate,
						DestinationCACertificate: testDestinationCACertificate,
					},
				},
			},
		},
		{
			name: "route with invalid certs should not be deprecated",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencypt.badconfig.test",
					TLS: &routev1.TLSConfig{
						Termination:              routev1.TLSTerminationReencrypt,
						Certificate:              "def",
						Key:                      "ghi",
						CACertificate:            "jkl",
						DestinationCACertificate: "abc",
					},
				},
			},
		},
		{
			name: "route with expired cert should not be deprecated",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.edge.expiredcert.test",
					TLS: &routev1.TLSConfig{
						Termination:   routev1.TLSTerminationEdge,
						Certificate:   testExpiredCert,
						Key:           testExpiredCertKey,
						CACertificate: testCACertificate,
					},
				},
			},
		},
		{
			name: "SHA1 certificate should be deprecated",
			route: &routev1.Route{
				Spec: routev1.RouteSpec{
					Host: "www.reencrypt.sha1.test",
					TLS: &routev1.TLSConfig{
						Termination: routev1.TLSTerminationReencrypt,
						Certificate: testCertificateRsaSha1,
						Key:         testCertificateRsaSha1Key,
					},
				},
			},
			deprecatedExpected: true,
		},
	}

	uidCount := 0
	nextUID := func() types.UID {
		uidCount++
		return types.UID(fmt.Sprintf("%03d", uidCount))
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.route.UID = nextUID()
			plugin.HandleRoute(watch.Added, tc.route)
			deprecated := rejections.isDeprecated(tc.route)
			if tc.deprecatedExpected != deprecated {
				t.Fatalf("expected to be deprecated=%t, got deprecated=%t", tc.deprecatedExpected, deprecated)
			}
		})
	}
}

func TestNamespaceScopingFromEmpty(t *testing.T) {
	router := newTestRouter(make(map[ServiceAliasConfigKey]ServiceAliasConfig))
	templatePlugin := newDefaultTemplatePlugin(router, true, nil)
	// TODO: move tests that rely on unique hosts to pkg/router/controller and remove them from
	// here
	plugin := controller.NewUniqueHost(templatePlugin, false, controller.LogRejections)

	// no namespaces allowed
	plugin.HandleNamespaces(sets.String{})

	//add
	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "test"},
		Spec: routev1.RouteSpec{
			Host: "www.example.com",
			To: routev1.RouteTargetReference{
				Name:   "TestService",
				Weight: new(int32),
			},
		},
	}

	// ignores all events for namespace that doesn't match
	for _, s := range []watch.EventType{watch.Added, watch.Modified, watch.Deleted} {
		plugin.HandleRoute(s, route)
		if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); ok || plugin.HostLen() != 0 {
			t.Errorf("unexpected router state %#v", router)
		}
	}

	// allow non matching
	plugin.HandleNamespaces(sets.NewString("bar"))
	for _, s := range []watch.EventType{watch.Added, watch.Modified, watch.Deleted} {
		plugin.HandleRoute(s, route)
		if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); ok || plugin.HostLen() != 0 {
			t.Errorf("unexpected router state %#v", router)
		}
	}

	// allow foo
	plugin.HandleNamespaces(sets.NewString("foo", "bar"))
	plugin.HandleRoute(watch.Added, route)
	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); !ok || plugin.HostLen() != 1 {
		t.Errorf("unexpected router state %#v", router)
	}

	// forbid foo, and make sure it's cleared
	plugin.HandleNamespaces(sets.NewString("bar"))
	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); ok || plugin.HostLen() != 0 {
		t.Errorf("unexpected router state %#v", router)
	}
	plugin.HandleRoute(watch.Modified, route)
	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); ok || plugin.HostLen() != 0 {
		t.Errorf("unexpected router state %#v", router)
	}
	plugin.HandleRoute(watch.Added, route)
	if _, ok := router.FindServiceUnit(endpointsKeyFromParts("foo", "TestService")); ok || plugin.HostLen() != 0 {
		t.Errorf("unexpected router state %#v", router)
	}
}
