#ifndef RA_COMMON_H
#define RA_COMMON_H

#include <stddef.h>
#include <stdint.h>

static const char QUOTE_MSG_FILE[] = "quote.msg";
static const char QUOTE_PCRS_FILE[] = "quote.pcrs";
static const char QUOTE_SIG_FILE[] = "quote.sig";
static const char EKPUB_PEM_FILE[] = "ekpub.pem";

static const char UDS_FILE[] = "/tmp/sock.uds";

#define GOTO_ON_ERROR(res, label, on_success, on_failure) \
    do                                                    \
    {                                                     \
        if ((res) != 0)                                   \
        {                                                 \
            printf("%s", (on_failure));                   \
            goto label;                                   \
        }                                                 \
        else                                              \
        {                                                 \
            printf("%s", (on_success));                   \
        }                                                 \
    } while (0)

enum Level
{
    CLIENT_HELLO = 1,
    SERVER_ATTESTATION_QUERY = 2,
    CLIENT_ATTESTATION_RESPONSE = 3,
    SERVER_ATTESTATION_DECISION = 4,
};

enum AttestationDecision
{
    CLIENT_ACCEPTED = 1,
    CLIENT_DECLINED = 2,
};

typedef struct
{
} payload_client_hello_t;

typedef struct
{
    uint8_t pcrList[32];
    uint16_t pcrListSize;
    uint8_t nonce[50];
    uint16_t nonceSize;
} payload_attestation_query_t;

typedef struct
{
    uint8_t quoteSignature[512];
    uint16_t quoteSignatureSize;
    uint8_t quotePCRs[1024];
    uint16_t quotePCRsSize;
    uint8_t quoteMessage[256];
    uint16_t quoteMessageSize;

    // The certificates are stored here in DER format
    // For our certificates, they are always a bit smaller than 1000 bytes.
    // We expect a certificate chain of length 5.
    // So, give a 5 * 1000 bytes buffer
    uint8_t certChain[5000];

    // first element is length of chain
    // Array size must be at least length of chain + 1
    uint16_t certLens[8];
} payload_attestation_data_t;

typedef struct
{
    enum AttestationDecision decision;
} payload_attestation_decision_t;

typedef struct
{
    enum Level packetType;
    union
    {
        payload_client_hello_t clientHello;
        payload_attestation_query_t attestationQuery;
        payload_attestation_data_t attestationResponse;
        payload_attestation_decision_t attestationDecision;
    };
} packet_t;

int receivePacket(packet_t *buffer, int socketfd, enum Level expectedPacketType);
int sendPacket(int socketFd, packet_t *buffer);
void bytesToHexString(char *target, const size_t targetLength, const uint8_t *bytes, const size_t bytesLength);
int executeCommand(const char *command);

#endif /* RA_COMMON_H */
