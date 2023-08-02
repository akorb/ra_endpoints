#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#include <stdint.h>

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

static const uint8_t crt_manufacturer[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDTDCCAjSgAwIBAgIBATANBgkqhkiG9w0BAQsFADA2MQ8wDQYDVQQDDAZ0aGUg\n\
Q04xFTATBgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMCAXDTIzMDcy\n\
NTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA2MQ8wDQYDVQQDDAZ0aGUgQ04xFTAT\n\
BgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMIIBIjANBgkqhkiG9w0B\n\
AQEFAAOCAQ8AMIIBCgKCAQEA2HE1cH0yIaOv/8Vlubx7B2hVxIqBA/FZotYuuwYp\n\
ZzSCUbwUdfMetZotrN/NleaviE4Vs8EB44Wy47cgyLW9AAyfHJeZjujh4W2asURD\n\
KHco4ndZi21tr5xGY0yzYYzeRCREz1M1JhaBcQqXbjBtVyzAwt4Qucar3rPX9LWl\n\
LiT31gEyF45ydSWNHwIKr2GCwGglAuiqVn3523ipEa2g/18MImi5vKfTeMLTNpYk\n\
egEGtzCRGhbJEZ05zS6AyE1sEbiWjjJVupjn0M0GLfOMAQA3ouiRydeEgTOafTfG\n\
J6Fn/QdqkcCJjBowZ/w0cPKXvAnMQr0P46eZ4LtJsuq1/QIDAQABo2MwYTAPBgNV\n\
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBQTIRgKPsm///DRXKoi0SXsf/H4xTAfBgNV\n\
HSMEGDAWgBQTIRgKPsm///DRXKoi0SXsf/H4xTAOBgNVHQ8BAf8EBAMCAgQwDQYJ\n\
KoZIhvcNAQELBQADggEBAG0dWzKxIaIFrc7x60oPStATMkmJ8YPi9rEKkHHFY7q5\n\
d8UFWIothbBQrddsMaiVY09qJA1RvuB6p5efXGGbdSGDcYG152NiwLkJ+KhSMft9\n\
z+qodML9D/4nAnFsWHaafl+GjvkE2axSw477DPbw4le9wj+F4mySBqSmKiD9dQsF\n\
nH6aJf7t85hqxCcq5pCWCQyMG0whD/wW6DrjBDfUlHA9toJE28fAwHR66LD/FcBC\n\
6OeTIgyT2DZf5sCODWxmtfOYTr7fBpLAAQ0ywf3LowKqZCrURxr6vgvG3k9S96MF\n\
nQCUQyBfIqSxyNrdZkyfOJw3FDZBVOcZUDNK4szugFM=\n\
-----END CERTIFICATE-----";

#endif /* RA_VERIFIER_H */
