#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>       /* Definition of O_* constants */
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>

#include <tee_client_api.h>
#include <fTPM.h>

#include "common.h"

static const TEEC_UUID ftpmTEEApp = TA_FTPM_UUID;

static int unloadFtpmModule(void)
{
    int res = syscall(SYS_delete_module, "tpm_ftpm_tee", O_NONBLOCK);
    if (res == -1)
    {
        perror(__func__);
    }
    return res;
}

static int loadFtpmModule(void)
{
    int moduleFd = open("/lib/modules/extra/tpm_ftpm_tee.ko", O_RDONLY);
    int res = syscall(SYS_finit_module, moduleFd, "", 0);
    if (res == -1)
    {
        perror(__func__);
    }
    close(moduleFd);
    return res;
}

static TEEC_Result invoke_ftpm_ta(uint8_t *bufferCrts, size_t bufferCrtsLen,
                                  uint16_t *crtSizes, size_t crtSizesSize)
{
    /* Allocate TEE Client structures on the stack. */
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_Result result;

    /**
     * Possible values from the TEE Client API Specification:
     * 1: the TEE Client API implementation
     * 2: the underlying communications stack linking the rich OS with the TEE
     * 3: the common TEE code
     * 4: the Trusted Application code
     */
    uint32_t errOrigin;

    /* ========================================================================
    [1] Connect to TEE
    ======================================================================== */
    result = TEEC_InitializeContext(
        NULL,
        &context);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_InitializeContext failed with code 0x%x\n", result);
        goto cleanup1;
    }
    /* ========================================================================
    [2] Open session with TEE application
    ======================================================================== */
    /* Open a Session with the TEE application. */
    result = TEEC_OpenSession(
        &context,
        &session,
        &ftpmTEEApp,
        TEEC_LOGIN_PUBLIC,
        NULL, /* No connection data needed for TEEC_LOGIN_PUBLIC. */
        NULL, /* No payload, and do not want cancellation. */
        &errOrigin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_OpenSession failed with code 0x%x origin 0x%x\n",
               result, errOrigin);
        goto cleanup2;
    }

    /* Clear the TEEC_Operation struct */
    memset(&operation, 0, sizeof(operation));

    /*
     * Prepare the arguments.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = bufferCrts;
    operation.params[0].tmpref.size = bufferCrtsLen;

    operation.params[1].tmpref.buffer = crtSizes;
    operation.params[1].tmpref.size = crtSizesSize;

    result = TEEC_InvokeCommand(&session, TA_FTPM_ATTEST,
                                &operation, &errOrigin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
               result, errOrigin);
        goto cleanup3;
    }

    /*
     * We're done with the TA, close the session and
     * destroy the context.
     */

cleanup3:
    TEEC_CloseSession(&session);
cleanup2:
    TEEC_FinalizeContext(&context);
cleanup1:
    return result;
}

static int getCertChain(uint8_t *bufferCrts, size_t bufferCrtsLen, uint16_t *bufferSizes, size_t bufferSizesLen)
{
    printf("Invoke fTPM TA to attest itself... ");
    invoke_ftpm_ta(bufferCrts, bufferCrtsLen,
                   bufferSizes, bufferSizesLen);
    printf("Success\n\n");

    return 0;
}

static int doAttestation(packet_t *buffer, const uint8_t *pcrList, size_t pcrListSize, const uint8_t *nonce, size_t nonceSize)
{
    // Unload ftpm_mod module if loaded already, to ensure we can access the fTPM TA for getting the cert chain
    unloadFtpmModule();
    getCertChain(buffer->attestationResponse.certChain, sizeof(buffer->attestationResponse.certChain),
                 buffer->attestationResponse.certLens, sizeof(buffer->attestationResponse.certLens));
    loadFtpmModule();
    executeCommand("tpm2_createek -c ek.ctx -t");
    executeCommand("tpm2_startauthsession -Q --policy-session -S session.ctx");
    executeCommand("tpm2_policysecret -Q -S session.ctx -c e -L secret.policy");

    // Get quote with nonce of server (tpm2_quote -c ek.ctx)
    // + 1 for null terminator
    char nonce_str[nonceSize * 2 + 1];
    bytesToHexString(nonce_str, sizeof(nonce_str), nonce, nonceSize);
    const char quote_cmd_template[] = "tpm2_quote -Q -c ek.ctx -g sha256 -l %s -q %s -p session:session.ctx -o quote.pcrs -m quote.msg -s quote.sig";
    char quote_cmd[sizeof(quote_cmd_template) - 2 - 1 + sizeof(nonce_str) + pcrListSize];
    snprintf(quote_cmd, sizeof(quote_cmd), quote_cmd_template, pcrList, nonce_str);
    executeCommand(quote_cmd);

    return 0;
}

static int sendClientHello(int socketFd, packet_t *buffer)
{
    printf("Send CLIENT_HELLO\n");
    buffer->packetType = CLIENT_HELLO;
    return sendPacket(socketFd, buffer);
}

static int readWholeFile(const char *filename, uint8_t *buffer, const size_t bufferSize, uint16_t *actualFilesize)
{
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize > bufferSize)
    {
        printf("%s: File %s bigger than buffer. Buffer: %ld, File: %ld.\n", __func__, filename, bufferSize, fsize);
        fclose(f);
        return 1;
    }

    *actualFilesize = fsize;

    fread(buffer, fsize, 1, f);
    fclose(f);

    return 0;
}

static int readAttestationFiles(uint8_t *quoteMessage, size_t maxQuoteMessageSize, uint16_t *quoteMessageSize,
                                uint8_t *quotePCRs, size_t maxQuotePCRsSize, uint16_t *quotePCRsSize,
                                uint8_t *quoteSignature, size_t maxQuoteSignatureSize, uint16_t *quoteSignatureSize)
{
    readWholeFile(QUOTE_MSG_FILE, quoteMessage, maxQuoteMessageSize, quoteMessageSize);
    readWholeFile(QUOTE_PCRS_FILE, quotePCRs, maxQuotePCRsSize, quotePCRsSize);
    readWholeFile(QUOTE_SIG_FILE, quoteSignature, maxQuoteSignatureSize, quoteSignatureSize);

    return 0;
}

static int sendAttestationResponse(int socketFd, packet_t *buffer)
{
    printf("Send CLIENT_ATTESTATION_RESPONSE\n");
    buffer->packetType = CLIENT_ATTESTATION_RESPONSE;
    return sendPacket(socketFd, buffer);
}

void printDecision(enum AttestationDecision decision)
{
    switch (decision)
    {
    case CLIENT_ACCEPTED:
        printf("The verifier accepted us.\n");
        break;

    case CLIENT_DECLINED:
        printf("The verifier declined us.\n");
        break;

    default:
        printf("Unknown decision value.\n");
        break;
    }
}

int main(void)
{
    int active_socket;
    packet_t *buffer = malloc(sizeof(packet_t));
    struct sockaddr_un address;
    if ((active_socket = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return 1;
    }

    address.sun_family = AF_LOCAL;
    strcpy(address.sun_path, UDS_FILE);
    if (connect(active_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("connect");
        return 1;
    }
    printf("Connected to server!\n");

    sendClientHello(active_socket, buffer);

    if (receivePacket(buffer, active_socket, SERVER_ATTESTATION_QUERY) != 0)
        return 1;

    doAttestation(buffer, buffer->attestationQuery.pcrList, buffer->attestationQuery.pcrListSize, buffer->attestationQuery.nonce, buffer->attestationQuery.nonceSize);
    readAttestationFiles(
        buffer->attestationResponse.quoteMessage, sizeof(buffer->attestationResponse.quoteMessage), &buffer->attestationResponse.quoteMessageSize,
        buffer->attestationResponse.quotePCRs, sizeof(buffer->attestationResponse.quotePCRs), &buffer->attestationResponse.quotePCRsSize,
        buffer->attestationResponse.quoteSignature, sizeof(buffer->attestationResponse.quoteSignature), &buffer->attestationResponse.quoteSignatureSize);

    sendAttestationResponse(active_socket, buffer);

    if (receivePacket(buffer, active_socket, SERVER_ATTESTATION_DECISION) != 0)
        return 1;

    printDecision(buffer->attestationDecision.decision);

    close(active_socket);
    free(buffer);
    return EXIT_SUCCESS;
}
