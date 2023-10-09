#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

#include <DiceTcbInfo.h>

#include "common.h"
#include "cert_root.h"
#include "ra_verifier.h"

// ASN1 encoded
static const uint8_t diceAttestationOid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

static const chain_t chainInfo[] = {
    CHAIN_ENTRY("bl1", "bl1.crt"),
    CHAIN_ENTRY("bl2", "bl2.crt"),
    CHAIN_ENTRY("bl31", "bl31.crt"),
    CHAIN_ENTRY("bl32", "bl32.crt"),
    CHAIN_ENTRY("fTPM", "ekcert.crt"),
};

static mbedtls_x509_crt *getEkCert(mbedtls_x509_crt *crtChain)
{
    // The EK certificate is the last certificate in the chain
    mbedtls_x509_crt *crt = crtChain;
    while (crt->next)
    {
        crt = crt->next;
    }
    return crt;
}

static int writeCertificateChain(mbedtls_x509_crt *crtChain)
{
    uint8_t fileBuffer[2048];
    size_t olen;

    const int availableNamesCount = ARRAY_LEN(chainInfo);

    for (int i = 0; crtChain != NULL; crtChain = crtChain->next, i++)
    {
        if (!(i < availableNamesCount))
        {
            printf("We try to write more certificates than we have filenames available\ni=%d, Available names count=%d", i, availableNamesCount);
            return 1;
        }

        mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                 crtChain->raw.p, crtChain->raw.len,
                                 fileBuffer, sizeof(fileBuffer),
                                 &olen);

        FILE *pemFile = fopen(chainInfo[i].certFilename, "wb");
        // - 1 to trim the null terminator
        // This ensures the exact same content as the certificate is embedded in the attestation PTA,
        // and how it is written here.
        fwrite(fileBuffer, 1, olen - 1, pemFile);
        fclose(pemFile);
    }

    return 0;
}

static void findX509ExtByOid(const mbedtls_x509_crt *cert, const uint8_t *extensionOid, const size_t oidSize,
                             uint8_t **extAddr, int *extDataSize)
{
    // Inspired by https://stackoverflow.com/a/75115264/2050020

    uint8_t *result = NULL;
    mbedtls_x509_buf buf;
    mbedtls_asn1_sequence extns;
    mbedtls_asn1_sequence *next;

    memset(&extns, 0, sizeof(extns));
    size_t tagLen;
    buf = cert->v3_ext;
    *extDataSize = 0;
    if (mbedtls_asn1_get_sequence_of(&buf.p, buf.p + buf.len, &extns, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
    {
        goto exit;
    }
    next = &extns;
    while (next)
    {
        if (mbedtls_asn1_get_tag(&(next->buf.p), next->buf.p + next->buf.len, &tagLen, MBEDTLS_ASN1_OID))
        {
            goto exit;
        }
        if (tagLen == oidSize && !memcmp(next->buf.p, extensionOid, tagLen))
        {
            uint8_t *p = next->buf.p + tagLen;
            *extDataSize = next->buf.len - tagLen - 2;
            result = p;
            break;
        }
        next = next->next;
    }

exit:
    mbedtls_asn1_sequence_free(extns.next);
    *extAddr = result;
}

static int parseAttestationExtension(uint8_t *addr, int extDataSize,
                                     uint8_t *outBuf, size_t outBufSize)
{
    // Skip the first two bytes since this only contains the octet string tag and its containing data length
    // See https://lapo.it/asn1js/#BDMwMaYvMC0GCWCGSAFlAwQCAQQgTM76aH04vo_hhcC_krKM22noJ-DiOSC-LM9KsroN6WA
    // for a full example what data can be input here with the `addr` argument
    addr += 2;
    extDataSize -= 2;

    DiceTcbInfo_t *tcbInfo = NULL;

    asn_dec_rval_t rval = ber_decode(0, &asn_DEF_DiceTcbInfo, (void **)&tcbInfo, addr, extDataSize);
    if (rval.code != 0)
    {
        printf("ber_decode failed, and returned %d.\n", rval.code);
        return rval.code;
    }
    if (tcbInfo->fwids->list.count != 1)
    {
        printf("We expect only one FWID for the time being.\n");
        return 1;
    }

    const struct FWID *fwid = tcbInfo->fwids->list.array[0];

    if (fwid->hashAlg.size != MBEDTLS_OID_SIZE(MBEDTLS_OID_DIGEST_ALG_SHA256) ||
        memcmp(fwid->hashAlg.buf, MBEDTLS_OID_DIGEST_ALG_SHA256, fwid->hashAlg.size) != 0)
    {
        printf("We only expect SHA256 values.\n");
        return 1;
    }

    if (outBufSize < fwid->digest.size)
    {
        printf("FWID does not fit in given buffer.\n");
        return 1;
    }

    memcpy(outBuf, fwid->digest.buf, fwid->digest.size);

    ASN_STRUCT_FREE(asn_DEF_DiceTcbInfo, tcbInfo);

    return 0;
}

static int printInfosOfCertificateChain(mbedtls_x509_crt *crtChain, mbedtls_x509_crt *crtRoot)
{
    uint8_t pubKey[256];
    char subject[64];
    const char subjectTemplate[] = "Cert [%d]: Subject: %s\n";
    const char subjectKeyTemplate[] = "          Subject key: %02X %02X %02X %02X ...\n";

    // Handle root certificate separately because it doesn't have a FWID to print

    // Print Subject of root certificate
    mbedtls_x509_dn_gets(subject, sizeof(subject), &crtRoot->subject);
    printf(subjectTemplate, 0, subject);

    // Print Subject key of root certificate
    mbedtls_mpi_write_binary(&mbedtls_pk_rsa(crtRoot->pk)->N, pubKey, sizeof(pubKey));
    printf(subjectKeyTemplate, pubKey[0], pubKey[1], pubKey[2], pubKey[3]);

    for (int i = 0; crtChain != NULL; crtChain = crtChain->next, i++)
    {
        if (crtChain->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
        {
            printf("We only support RSA certificates so far.\n");
            return 1;
        }

        // Print Subject
        mbedtls_x509_dn_gets(subject, sizeof(subject), &crtChain->subject);
        printf(subjectTemplate, i + 1, subject);

        // Print Subject Key
        mbedtls_mpi_write_binary(&mbedtls_pk_rsa(crtChain->pk)->N, pubKey, sizeof(pubKey));
        printf(subjectKeyTemplate, pubKey[0], pubKey[1], pubKey[2], pubKey[3]);

        // Print FWID
        uint8_t *extAddr;
        int extDataLen;
        uint8_t fwid[SHA256_LEN];
        findX509ExtByOid(crtChain, diceAttestationOid, sizeof(diceAttestationOid), &extAddr, &extDataLen);
        if (extAddr != NULL)
        {
            parseAttestationExtension(extAddr, extDataLen, fwid, sizeof(fwid));

            printf("          FWID: ");
            for (size_t j = 0; j < SHA256_LEN; j++)
            {
                printf("%02X ", fwid[j]);
            }
            printf("\n");
        }
    }

    return 0;
}

static int verifyCertificateChainSignatures(mbedtls_x509_crt *crtChain, mbedtls_x509_crt *crtRoot)
{
    // From https://stackoverflow.com/a/72722115/2050020

    int res;
    uint32_t flags = 0;
    if ((res = mbedtls_x509_crt_verify(crtChain, crtRoot, NULL, NULL, &flags,
                                       NULL, NULL)) != 0)
    {
        char verifyBuf[512];
        mbedtls_x509_crt_verify_info(verifyBuf, sizeof(verifyBuf), "  ! ", flags);
        printf("Verification of certificate signatures failed. Reason: %s\n", verifyBuf);
        printf("    Error: 0x%04x; flag: %u\n", res, flags);
    }

    return res;
}

static int parseCrtFromBuffer(mbedtls_x509_crt *crt, const uint8_t *inBuf, const size_t inBufSize, const char *certName)
{
    int res = mbedtls_x509_crt_parse(crt, inBuf, inBufSize);
    if (res != 0)
    {
        char errorBuf[256];
        mbedtls_strerror(res, errorBuf, sizeof(errorBuf));
        printf(" parsing %s failed\n  !  mbedtls_x509_crt_parse returned -0x%x - %s\n",
               certName, (unsigned int)-res, errorBuf);
    }
    return res;
}

static int isDigitalSignatureKey(mbedtls_x509_crt *crt)
{
    /**
     * mbedtls_x509_crt_check_key_usage also says the usage value is fine
     * if the key usage is absent. We don't want that. So, we check it in advance.
     */
    if ((crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0)
    {
        printf("Key usage extension is absent.\n");
        return 0;
    }
    int res = mbedtls_x509_crt_check_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if (res == MBEDTLS_ERR_X509_BAD_INPUT_DATA)
    {
        printf("Key usage extension is not assigned as digital signature.\n");
        const size_t bufSize = 16384;
        char *buf = malloc(bufSize);
        buf[0] = 0;
        if (mbedtls_x509_crt_info(buf, bufSize, "  ", crt) > 0)
            printf("%s\n", buf);
        free(buf);
    }
    return res == 0;
}

static int parseCrtChainFromBuffer(const uint8_t *bufferCrts, const size_t bufferCrtsSize,
                                   const uint16_t *bufferSizes, const size_t bufferSizesSize,
                                   mbedtls_x509_crt *crtChain)
{
    int certificateCount = bufferSizes[0];

    const uint16_t *sizes = &bufferSizes[1];
    const uint8_t *curCrt = bufferCrts;

    for (int i = 0; i < certificateCount; i++)
    {
        assert(&sizes[i] + sizeof(sizes[0]) < &bufferSizes[bufferSizesSize]);
        assert(curCrt + sizes[i] < &bufferCrts[bufferCrtsSize]);

        int res = parseCrtFromBuffer(crtChain, curCrt, sizes[i], chainInfo[i].certFilename);
        if (res != 0)
            return res;

        curCrt += sizes[i];
    }

    return 0;
}

static int writeFile(const char *filename, const uint8_t *buffer, const size_t bufferSize)
{
    FILE *f = fopen(filename, "w");
    size_t bytesWritten = fwrite(buffer, 1, bufferSize, f);
    if (bytesWritten != bufferSize)
    {
        printf("%s:%s:%d: fwrite failed. Wrote only %ld bytes instead of %ld\n", __FILE__, __func__, __LINE__, bytesWritten, bufferSize);
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

static int writeSubjectKeyToPemFile(const char *filename, const mbedtls_x509_crt *crt)
{
    uint8_t buffer[1024];
    int res = mbedtls_pk_write_pubkey_pem(&crt->pk, buffer, sizeof(buffer));
    if (res != 0)
    {
        char errorBuf[256];
        mbedtls_strerror(res, errorBuf, sizeof(errorBuf));
        printf(" writing public key failed\n  !  mbedtls_pk_write_pubkey_pem returned -0x%x - %s\n",
               (unsigned int)-res, errorBuf);
        return 1;
    }

    res = writeFile(filename, buffer, strlen((const char *)buffer) + 1);
    return res;
}

static int writeAttestationResponseToFiles(const packet_t *buffer, const mbedtls_x509_crt *ekCert)
{
    writeFile(QUOTE_MSG_FILE, buffer->attestationResponse.quoteMessage, buffer->attestationResponse.quoteMessageSize);
    writeFile(QUOTE_PCRS_FILE, buffer->attestationResponse.quotePCRs, buffer->attestationResponse.quotePCRsSize);
    writeFile(QUOTE_SIG_FILE, buffer->attestationResponse.quoteSignature, buffer->attestationResponse.quoteSignatureSize);

    return writeSubjectKeyToPemFile(EKPUB_PEM_FILE, ekCert);
}

int verifyCertificateChain(const packet_t *buffer, const mbedtls_x509_crt *crtChain, const mbedtls_x509_crt *crtRoot)
{
    int res;

    // Disable buffering of stdout since we write some lines without trailing "\n"
    // which wouldn't be visible until writing a new line otherwise.
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Verify signature of each certificate in chain rooted in embedded root certificate... ");
    res = verifyCertificateChainSignatures(crtChain, crtRoot);
    GOTO_ON_ERROR(res, error, "Signatures valid\n\n", "Signatures invalid\n\n");

    printf("Write certificates retrieved from fTPM TA to hard disk for further investigation... ");
    res = writeCertificateChain(crtChain);
    GOTO_ON_ERROR(res, error, "Success\n\n", "Failed\n\n");

    printf("Ensure that the subject key is assigned as a restricted signing key\n");
    printf("Note that this value is only reliable if we also trust all the FWIDs... ");
    // Need to negate the return value because of different semantics of the int value
    // Required to keep the "is*" semantic of the isDigitalSignatureKey function, i.e., 1 = good, 0 = bad, which is vice versa for other functions
    res = !isDigitalSignatureKey(getEkCert(crtChain));
    GOTO_ON_ERROR(res, error, "Good\n\n", "Bad\n\n");

error:
    return res;
}

static void FillWithRandomData(uint8_t *data, const size_t dataSize)
{
    srand(time(NULL));

    for (size_t i = 0; i < dataSize; i++)
    {
        data[i] = (uint8_t)rand();
    }
}

static int verifyAndPrintAttestationData(const uint8_t *nonce, const size_t nonceSize)
{
    char nonce_str[nonceSize * 2 + 1];
    bytesToHexString(nonce_str, sizeof(nonce_str), nonce, nonceSize);

    const char check_quote_cmd_template[] = "tpm2_checkquote -u %s -m quote.msg -s quote.sig -f quote.pcrs -q %s";
    char check_quote_cmd[sizeof(check_quote_cmd_template) + sizeof(nonce_str) + sizeof(EKPUB_PEM_FILE)];
    snprintf(check_quote_cmd, sizeof(check_quote_cmd), check_quote_cmd_template, EKPUB_PEM_FILE, nonce_str);
    return executeCommand(check_quote_cmd);
}

static int sendAttestationQuery(int socketFd, packet_t *buffer)
{
    printf("Send SERVER_ATTESTATION_QUERY\n");
    buffer->packetType = SERVER_ATTESTATION_QUERY;
    return sendPacket(socketFd, buffer);
}

static int sendAttestationDecision(int socketFd, packet_t *buffer)
{
    printf("Send SERVER_ATTESTATION_DECISION\n");
    buffer->packetType = SERVER_ATTESTATION_DECISION;
    return sendPacket(socketFd, buffer);
}

static enum AttestationDecision decideIfClientIsTrustworthy(const packet_t *buffer, const uint8_t *nonce, const size_t nonceSize,
                                                            const mbedtls_x509_crt *crtChain, const mbedtls_x509_crt *crtRoot)
{
    int res;
    int answer;
    res = verifyCertificateChain(buffer, crtChain, crtRoot);
    GOTO_ON_ERROR(res, error, "Certificate chain trustworthy.\n", "Certificate chain not trustworthy.\n");

    printf("Print infos of certificate chain:\n");
    res = printInfosOfCertificateChain(crtChain, crtRoot);
    GOTO_ON_ERROR(res, error, "", "Failed\n\n");

    printf("Do you consider these FWIDs as trustworthy? (y/n) ");
    answer = getchar();
    flush_stdin();
    GOTO_ON_ERROR(answer != 'y', error, "", "");

    res = verifyAndPrintAttestationData(nonce, nonceSize);
    GOTO_ON_ERROR(res, error, "Quote is trustworthy.\n", "Quote is not trustworthy\n");

    printf("Do you consider these PCR values as trustworthy? (y/n) ");
    answer = getchar();
    flush_stdin();
    GOTO_ON_ERROR(answer != 'y', error, "", "");

    printf("Accepting client.\n");
    return CLIENT_ACCEPTED;

error:
    printf("Declining client.\n");
    return CLIENT_DECLINED;
}

static int parseAttestationResponse(const packet_t *buffer, mbedtls_x509_crt *crtChain)
{
    const uint8_t *bufferCrts = buffer->attestationResponse.certChain;
    const size_t bufferCrtsLen = sizeof(buffer->attestationResponse.certChain);
    const uint16_t *bufferSizes = buffer->attestationResponse.certLens;
    const size_t bufferSizesLen = sizeof(buffer->attestationResponse.certLens);

    printf("Parse received data containing the X509 certificates in DER format... ");

    int res = parseCrtChainFromBuffer(bufferCrts, bufferCrtsLen,
                                      bufferSizes, bufferSizesLen, crtChain);
    if (res == 0)
        printf("Success\n\n");

    return res;
}

static void serveClient(int activeSocket, mbedtls_x509_crt *crtRoot)
{
    printf("A client connected ...\n");
    packet_t *buffer = malloc(sizeof(packet_t));

    if (receivePacket(buffer, activeSocket, CLIENT_HELLO) != 0)
        return;

    const char pcrList[] = "sha1:0,1,2,3";
    memcpy(buffer->attestationQuery.pcrList, pcrList, sizeof(pcrList));
    uint8_t nonce[sizeof(buffer->attestationQuery.nonce)];
    FillWithRandomData(nonce, sizeof(nonce));
    memcpy(buffer->attestationQuery.nonce, nonce, sizeof(nonce));
    buffer->attestationQuery.nonceSize = sizeof(buffer->attestationQuery.nonce);
    buffer->attestationQuery.pcrListSize = sizeof(pcrList);
    sendAttestationQuery(activeSocket, buffer);

    if (receivePacket(buffer, activeSocket, CLIENT_ATTESTATION_RESPONSE) != 0)
        return;

    mbedtls_x509_crt crtChain;
    mbedtls_x509_crt_init(&crtChain);
    parseAttestationResponse(buffer, &crtChain);
    writeAttestationResponseToFiles(buffer, getEkCert(&crtChain));

    enum AttestationDecision decision = decideIfClientIsTrustworthy(buffer, nonce, sizeof(nonce), &crtChain, crtRoot);

    buffer->attestationDecision.decision = decision;
    sendAttestationDecision(activeSocket, buffer);

    mbedtls_x509_crt_free(&crtChain);
    free(buffer);
}

int main(void)
{
    int acceptSocket, activeSocket;
    socklen_t addrlen;
    struct sockaddr_un address;
    if ((acceptSocket = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return 1;
    }

    unlink(UDS_FILE);
    address.sun_family = AF_LOCAL;
    strcpy(address.sun_path, UDS_FILE);
    if (bind(acceptSocket,
             (struct sockaddr *)&address,
             sizeof(address)) == -1)
    {
        perror("bind");
        return 1;
    }
    if (listen(acceptSocket, 5) == -1)
    {
        perror("listen");
        return 1;
    }
    addrlen = sizeof(struct sockaddr);

    mbedtls_x509_crt crtRoot;
    mbedtls_x509_crt_init(&crtRoot);
    parseCrtFromBuffer(&crtRoot, crt_manufacturer, sizeof(crt_manufacturer), "crt_manufacturer");

    printf("Waiting for attestee to connect\n");
    while (1)
    {
        activeSocket = accept(acceptSocket,
                              (struct sockaddr *)&address,
                              &addrlen);
        if (activeSocket == -1)
        {
            perror("accept");
            continue;
        }

        serveClient(activeSocket, &crtRoot);

        close(activeSocket);
    }
    mbedtls_x509_crt_free(&crtRoot);
    close(acceptSocket);
    return EXIT_SUCCESS;
}
