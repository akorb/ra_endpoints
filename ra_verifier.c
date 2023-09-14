#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ra_verifier.h>

#include <tee_client_api.h>
#include <fTPM.h>

#include <DiceTcbInfo.h>
#include "TCIs.h"
#include "cert_root.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

static const chain_t chainInfo[] = {
    CHAIN_ENTRY_WITHOUT_TCI(bl1),
    CHAIN_ENTRY(bl2),
    CHAIN_ENTRY(bl31),
    CHAIN_ENTRY(bl32),
    CHAIN_ENTRY(ekcert),
};

static const TEEC_UUID ftpmTEEApp = TA_FTPM_UUID;

// ASN1 encoded
static const uint8_t diceAttestationOid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

static mbedtls_x509_crt *GetEkCert(mbedtls_x509_crt *crtChain)
{
    // The EK certificate is the last certificate in the chain
    mbedtls_x509_crt *crt = crtChain;
    while (crt->next)
    {
        crt = crt->next;
    }
    return crt;
}

static TEEC_Result invoke_ftpm_ta(uint8_t *bufferCrts, size_t bufferCrtsLen,
                                  uint16_t *crtSizes, size_t crtSizesSize,
                                  uint8_t *bufferSignature, size_t bufferSignatureSize,
                                  uint8_t *bufferToSignData, size_t bufferToSignDataSize)
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
                                            TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INPUT);
    operation.params[0].tmpref.buffer = bufferCrts;
    operation.params[0].tmpref.size = bufferCrtsLen;

    operation.params[1].tmpref.buffer = crtSizes;
    operation.params[1].tmpref.size = crtSizesSize;

    operation.params[2].tmpref.buffer = bufferSignature;
    operation.params[2].tmpref.size = bufferSignatureSize;

    operation.params[3].tmpref.buffer = bufferToSignData;
    operation.params[3].tmpref.size = bufferToSignDataSize;

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

static int parseCrtFromBuffer(mbedtls_x509_crt *crt, const uint8_t *inBuf, const size_t inBufSize, const char *certName)
{
    int res = mbedtls_x509_crt_parse(crt, inBuf, inBufSize);
    if (res != 0)
    {
        char errorBuf[256];
        mbedtls_strerror(res, errorBuf, sizeof(errorBuf));
        errx(EXIT_FAILURE, " parsing %s failed\n  !  mbedtls_x509_crt_parse returned -0x%x - %s\n",
             certName, (unsigned int)-res, errorBuf);
    }
    return res;
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

        parseCrtFromBuffer(crtChain, curCrt, sizes[i], chainInfo[i].certFilename);

        curCrt += sizes[i];
    }

    return 0;
}

static int writeCertificateChain(mbedtls_x509_crt *crtChain)
{
    uint8_t fileBuffer[2048];
    size_t olen;

    const int availableNamesCount = ARRAY_LEN(chainInfo);

    for (int i = 0; crtChain != NULL; crtChain = crtChain->next, i++)
    {
        if (!(i < availableNamesCount))
            errx(EXIT_FAILURE, "We try to write more certificates than we have filenames available\ni=%d, Available names count=%d", i, availableNamesCount);

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
        errx(EXIT_FAILURE, "ber_decode failed, and returned %d.", rval.code);
    }
    if (tcbInfo->fwids->list.count != 1)
    {
        errx(EXIT_FAILURE, "We expect only one FWID for the time being.");
    }

    const struct FWID *fwid = tcbInfo->fwids->list.array[0];

    if (fwid->hashAlg.size != MBEDTLS_OID_SIZE(MBEDTLS_OID_DIGEST_ALG_SHA256) ||
        memcmp(fwid->hashAlg.buf, MBEDTLS_OID_DIGEST_ALG_SHA256, fwid->hashAlg.size) != 0)
    {
        errx(EXIT_FAILURE, "We only expect SHA256 values.");
    }

    if (outBufSize < fwid->digest.size)
    {
        errx(EXIT_FAILURE, "FWID does not fit in given buffer.");
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

    // Handle root certificate separately because it doesn't have a TCI to print

    // Print Subject of root certificate
    mbedtls_x509_dn_gets(subject, sizeof(subject), &crtRoot->subject);
    printf(subjectTemplate, 0, subject);

    // Print Subject Key of root certificate
    mbedtls_mpi_write_binary(&mbedtls_pk_rsa(crtRoot->pk)->N, pubKey, sizeof(pubKey));
    printf(subjectKeyTemplate, pubKey[0], pubKey[1], pubKey[2], pubKey[3]);

    for (int i = 0; crtChain != NULL; crtChain = crtChain->next, i++)
    {
        if (crtChain->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
        {
            errx(EXIT_FAILURE, "We only support RSA certificates so far.\n");
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
        errx(EXIT_FAILURE, "Error: 0x%04x; flag: %u\n", res, flags);
    }

    return res;
}

static int verifyTcis(mbedtls_x509_crt *crtChain)
{
    for (int i = 0; crtChain != NULL; crtChain = crtChain->next, i++)
    {
        uint8_t *extAddr;
        int extDataLen;
        uint8_t fwid[SHA256_LEN];
        findX509ExtByOid(crtChain, diceAttestationOid, sizeof(diceAttestationOid), &extAddr, &extDataLen);
        if (extAddr != NULL && chainInfo[i].expectedTci != NULL)
        {
            parseAttestationExtension(extAddr, extDataLen, fwid, sizeof(fwid));

            printf("Checking trustworthiness of %-6s...", chainInfo[i].name);
            if (memcmp(fwid, chainInfo[i].expectedTci, sizeof(fwid)) == 0)
                printf(" Trusted\n");
            else
                printf(" Untrusted\n");
        }
    }
    return 0;
}

static int verifyDataSignature(uint8_t *data, size_t dataSize, uint8_t *signature, size_t signatureSize, mbedtls_pk_context *pk)
{
    // Get the message digest info structure for SHA256
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char *md = malloc(mdinfo->size);
    // Calculate the message digest for the data
    mbedtls_md(mdinfo, data, dataSize, md);

    // Has to match the hash algorithm we specify in the signing process within the fTPM!
    mbedtls_pk_rsassa_pss_options options;
    options.mgf1_hash_id = MBEDTLS_MD_SHA256;
    options.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;
    int res = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &options, pk,
                                    mdinfo->type, md, mdinfo->size,
                                    signature, signatureSize);

    if (res != 0)
    {
        char errorBuf[256];
        mbedtls_strerror(res, errorBuf, sizeof(errorBuf));
        errx(EXIT_FAILURE, "failed\n  !  mbedtls_pk_verify_ext returned -0x%x - %s\n",
             (unsigned int)-res, errorBuf);
    }

    free(md);

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

int main(void)
{
    // The certificates are stored here in DER format
    // For our certificates, they are always a bit smaller than 1000 bytes.
    // We expect a certificate chain of length 5.
    // So, give a 5 * 1000 bytes buffer
    uint8_t bufferCrts[5000];

    // first element is length of chain
    // Array size must be at least length of chain + 1
    uint16_t bufferSizes[8];

    // Disable buffering of stdout since we write some lines without trailing "\n"
    // which wouldn't be visible until writing a new line otherwise.
    setvbuf(stdout, NULL, _IONBF, 0);

    mbedtls_x509_crt crtChain, crtRoot;
    mbedtls_x509_crt_init(&crtChain);
    mbedtls_x509_crt_init(&crtRoot);

    parseCrtFromBuffer(&crtRoot, crt_manufacturer, sizeof(crt_manufacturer), "crt_manufacturer");

    uint8_t signature[256];
    uint8_t nonce[128];
    FillWithRandomData(nonce, sizeof(nonce));

    /**
     * All functions only return if they were successful.
     * This keeps the following code quite clean and easy to follow.
     */

    printf("Invoking fTPM TA with nonce to attest itself ...");
    invoke_ftpm_ta(bufferCrts, sizeof(bufferCrts),
                   bufferSizes, sizeof(bufferSizes),
                   signature, sizeof(signature),
                   nonce, sizeof(nonce));
    printf("Success\n\n");

    printf("Parsing returned buffers containing the X509 certificates in DER format... ");
    parseCrtChainFromBuffer(bufferCrts, sizeof(bufferCrts),
                 bufferSizes, sizeof(bufferSizes), &crtChain);
    printf("Success\n\n");

    printf("Print infos of certificate chain:\n");
    printInfosOfCertificateChain(&crtChain, &crtRoot);
    printf("\n");

    printf("Write certificates retrieved from fTPM TA to hard disk for further investigation... ");
    writeCertificateChain(&crtChain);
    printf("Success\n\n");

    printf("Verify signature of each certificate in chain rooted in embedded root certificate... ");
    verifyCertificateChainSignatures(&crtChain, &crtRoot);
    printf("Signatures valid\n\n");

    printf("Verify the signature of the nonce to ensure the TPM possesses the matching private key to the public key in the EKcert... ");
    verifyDataSignature(nonce, sizeof(nonce), signature, sizeof(signature), &GetEkCert(&crtChain)->pk);
    printf("Signature valid\n\n");

    printf("Check whether we consider the TCIs of the components as trustworthy:\n");
    printf("Verification of trustworthiness of software chain (BLn -> fTPM).\n");
    printf("Note that the TCI of bl2 changes on each compilation.\n");
    printf("So, you might want to keep it untrusted during development, and set the TCI only once right before deployment.\n");
    verifyTcis(&crtChain);

    /**
     * "The floors are like my children!"
     * - The Janitor (Scrubs Season 4, Ep. 24)
     * 
     * Let's be like the janitor and clean our stuff.
     */
    mbedtls_x509_crt_free(&crtChain);
    mbedtls_x509_crt_free(&crtRoot);

    return 0;
}
