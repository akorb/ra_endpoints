#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#include <stdint.h>

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

typedef struct {
    const char name[8];
    const char certFilename[10];
    const char *expectedTci;
} chain_t;

#define CHAIN_ENTRY(bl) \
    { \
        .name = #bl, \
        .certFilename=#bl".crt", \
        .expectedTci = tci_ ## bl, \
    }

#define CHAIN_ENTRY_WITHOUT_TCI(bl) \
    { \
        .name = #bl, \
        .certFilename=#bl".crt", \
        .expectedTci = NULL, \
    }

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#define SHA256_LEN (256 / 8)

/**
 * This is the certificiate of the manufacturer which needs to be inherently trusted
 * and therefore, acts as the root of trust for the certificate chain.
 */
static const uint8_t rootCrtPem[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDWDCCAkCgAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MRUwEwYDVQQDDAxNYW51\n\
ZmFjdHVyZXIxFTATBgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA8MRUwEwYDVQQDDAxNYW51\n\
ZmFjdHVyZXIxFTATBgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMIIB\n\
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmh2aVN2BGu7paDxpZXxUGcwP\n\
beH7F0K9uZ1rROU7Q0Q2rLZNNctbXP82stpuCG4uQsR1dUbnjXkPRVeo8cc9mJUR\n\
DZrzFzk0yz1pbzXsszbeV+6c2ENA7nYPeQyVcVnPAL2mSyzY+2+t2UUO0tL6HTSS\n\
Boc9xoxlECpDs31SxOjn6uZgg0iP26CUszDK1oLv62YEyHTevAKZEjmQS2nXi3xm\n\
oqtapKPMczzP2gdzwOpJrBOqpur7XVV32U44gX6Y1z8EfGW7WEtv9f0vm//Zd+rS\n\
PvI483OsqPEt94e5B/a5QiwCOiZjlALGB4uzarl69dVhjcXJAhGA1Re2sIy4JwID\n\
AQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTrzpN3AKEd61qbfATZ\n\
3V4M5BDP9DAfBgNVHSMEGDAWgBTrzpN3AKEd61qbfATZ3V4M5BDP9DAOBgNVHQ8B\n\
Af8EBAMCAgQwDQYJKoZIhvcNAQELBQADggEBAHYw+8wx9WKovMIzwv7xChIBN+ww\n\
VpXcifKGDL35vnOMeUoiLQH++4is9M+18w+5Vh5PEvZBGMka241uu5PqKAx9/rFl\n\
+jhSeYSFn0Jyz3T/fX7/U+S8iKnekIcKu/7exUL2DaT0gQMqbOXUaE+3xy4FvsHw\n\
qgXunBlroz8jznlaJvrHecPeJzdRS0btLqSJcYR3sRb6QCLvNsx2zWXMH+Xv8tsX\n\
YzGwGM6n5wxFc7R0UtrMYjWWArk1yzjPT/D9/IAs0eRTnWPaKIDOmUlRfuW+NLC+\n\
wKSoNRpzV3PMk+QhNX3JZ75lhO5qHuvda9ivIp44R9SYt6WvoV9rXWLMqys=\n\
-----END CERTIFICATE-----";

#endif /* RA_VERIFIER_H */
