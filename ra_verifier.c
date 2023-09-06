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

#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

static const chain_t chain_info[] = {
    CHAIN_ENTRY_WITHOUT_TCI(bl1),
    CHAIN_ENTRY(bl2),
    CHAIN_ENTRY(bl31),
    CHAIN_ENTRY(bl32),
    CHAIN_ENTRY(ekcert),
};

static const TEEC_UUID ftpmTEEApp = TA_FTPM_UUID;

// ASN1 encoded
static const uint8_t dice_attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

static mbedtls_x509_crt * GetEkCert(mbedtls_x509_crt *crt_ctx)
{
    // The EK certificate is the last certificate in the chain
    mbedtls_x509_crt *next = crt_ctx;
    while (next->next)
    {
        next = next->next;
    }
    return next;
}

static TEEC_Result invoke_ftpm_ta(uint8_t *buffer_crts, size_t buffer_crts_len,
                                  uint16_t *buffer_offsets, size_t buffer_offsets_len,
                                  uint8_t *buffer_signature, size_t buffer_signature_size,
                                  uint8_t *buffer_to_sign_data, size_t buffer_to_sign_data_size)
{
    /* Allocate TEE Client structures on the stack. */
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t err_origin;

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
        &err_origin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_OpenSession failed with code 0x%x origin 0x%x\n",
               result, err_origin);
        goto cleanup2;
    }

    /* Clear the TEEC_Operation struct */
    memset(&operation, 0, sizeof(operation));

    /*
     * Prepare the arguments.
     */
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INPUT);
    operation.params[0].tmpref.buffer = buffer_crts;
    operation.params[0].tmpref.size = buffer_crts_len;

    operation.params[1].tmpref.buffer = buffer_offsets;
    operation.params[1].tmpref.size = buffer_offsets_len;

    operation.params[2].tmpref.buffer = buffer_signature;
    operation.params[2].tmpref.size = buffer_signature_size;

    operation.params[3].tmpref.buffer = buffer_to_sign_data;
    operation.params[3].tmpref.size = buffer_to_sign_data_size;

    printf("Invoking fTPM TA to attest itself... \n");
    result = TEEC_InvokeCommand(&session, TA_FTPM_ATTEST,
                                &operation, &err_origin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
               result, err_origin);
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

static int parse_crt_from_buffer(mbedtls_x509_crt *crt_ctx, const uint8_t *crt_buf, const size_t crt_len, const char *cert_name)
{
    int res = mbedtls_x509_crt_parse(crt_ctx, crt_buf, crt_len);
    if (res != 0)
    {
        char error_buf[256];
        mbedtls_strerror(res, error_buf, 256);
        printf(" parsing %s failed\n  !  mbedtls_x509_crt_parse returned -0x%x - %s\n",
               cert_name, (unsigned int)-res, error_buf);
    }
    return res;
}

static int parse_buffers(const uint8_t *buffer_crts, const size_t buffer_crts_len,
                         const uint16_t *buffer_sizes, const size_t buffer_sizes_len,
                         mbedtls_x509_crt *crt_ctx)
{
    int res;
    int certificate_count = buffer_sizes[0];

    const uint16_t *sizes = &buffer_sizes[1];
    const uint8_t *cur_crt = buffer_crts;

    for (int i = 0; i < certificate_count; i++)
    {
        assert(&sizes[i] + sizeof(sizes[0]) < &buffer_sizes[buffer_sizes_len]);
        assert(cur_crt + sizes[i] < &buffer_crts[buffer_crts_len]);

        res = parse_crt_from_buffer(crt_ctx, cur_crt, sizes[i], chain_info[i].cert_filename);
        if (res != 0)
            return res;

        cur_crt += sizes[i];
    }

    return 0;
}

static int write_certificates(mbedtls_x509_crt *crt_ctx)
{
    uint8_t file_buffer[2048];
    size_t olen;

    const int count_available_names = ARRAY_LEN(chain_info);

    for (int i = 0; crt_ctx != NULL; crt_ctx = crt_ctx->next, i++)
    {
        if (!(i < count_available_names))
            errx(EXIT_FAILURE, "We try to write more certificates than we have filenames available\ni=%d, Available names count=%d", i, count_available_names);

        mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                 crt_ctx->raw.p, crt_ctx->raw.len,
                                 file_buffer, sizeof(file_buffer),
                                 &olen);

        FILE *pem_file = fopen(chain_info[i].cert_filename, "wb");
        // - 1 to trim the null terminator
        // This ensures the exact same content as the certificate is embedded in the attestation PTA,
        // and how it is written here.
        fwrite(file_buffer, 1, olen - 1, pem_file);
        fclose(pem_file);
    }

    return 0;
}

static void find_ext_by_oid(const mbedtls_x509_crt *cert, const uint8_t *extension_oid, const size_t oid_len,
                            uint8_t **ext_addr, int *extension_data_length)
{
    // Inspired by https://stackoverflow.com/a/75115264/2050020

    uint8_t *result = NULL;
    mbedtls_x509_buf buf;
    mbedtls_asn1_sequence extns;
    mbedtls_asn1_sequence *next;

    memset(&extns, 0, sizeof(extns));
    size_t tag_len;
    buf = cert->v3_ext;
    *extension_data_length = 0;
    if (mbedtls_asn1_get_sequence_of(&buf.p, buf.p + buf.len, &extns, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
    {
        goto exit;
    }
    next = &extns;
    while (next)
    {
        if (mbedtls_asn1_get_tag(&(next->buf.p), next->buf.p + next->buf.len, &tag_len, MBEDTLS_ASN1_OID))
        {
            goto exit;
        }
        if (tag_len == oid_len && !memcmp(next->buf.p, extension_oid, tag_len))
        {
            uint8_t *p = next->buf.p + tag_len;
            *extension_data_length = next->buf.len - tag_len - 2;
            result = p;
            break;
        }
        next = next->next;
    }

exit:
    mbedtls_asn1_sequence_free(extns.next);
    *ext_addr = result;
}

static int parse_attestation_extension(uint8_t *addr, int ext_data_len,
                                       uint8_t *out_buf, size_t out_buf_len)
{
    // Skip the first two bytes since this only contains the octet string tag and its containing data length
    // See https://lapo.it/asn1js/#BDMwMaYvMC0GCWCGSAFlAwQCAQQgTM76aH04vo_hhcC_krKM22noJ-DiOSC-LM9KsroN6WA
    // for a full example what data can be input here with the `addr` argument
    addr += 2;
    ext_data_len -= 2;

    DiceTcbInfo_t *tcbInfo = NULL;

    asn_dec_rval_t rval = ber_decode(0, &asn_DEF_DiceTcbInfo, (void **)&tcbInfo, addr, ext_data_len);
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

    if (out_buf_len < fwid->digest.size)
    {
        errx(EXIT_FAILURE, "FWID does not fit in given buffer.");
    }

    memcpy(out_buf, fwid->digest.buf, fwid->digest.size);

    ASN_STRUCT_FREE(asn_DEF_DiceTcbInfo, tcbInfo);

    return 0;
}

static int print_infos_of_certificates(mbedtls_x509_crt *crt_ctx, mbedtls_x509_crt *root_crt)
{
    uint8_t pubKey[256];
    char subject[64];
    const char subjectTemplate[] = "Cert [%d]: Subject: %s\n";
    const char subjectKeyTemplate[] = "          Subject key: %02X %02X %02X %02X ...\n";

    // Print Subject of root certificate
    mbedtls_x509_dn_gets(subject, sizeof(subject), &root_crt->subject);
    printf(subjectTemplate, 0, subject);

    // Print Subject Key of root certificate
    mbedtls_mpi_write_binary(&mbedtls_pk_rsa(root_crt->pk)->N, pubKey, sizeof(pubKey));
    printf(subjectKeyTemplate, pubKey[0], pubKey[1], pubKey[2], pubKey[3]);

    for (int i = 0; crt_ctx != NULL; crt_ctx = crt_ctx->next, i++)
    {
        if (crt_ctx->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
        {
            printf("We only support RSA certificates so far.\n");
            return -1;
        }

        // Print Subject
        mbedtls_x509_dn_gets(subject, sizeof(subject), &crt_ctx->subject);
        printf(subjectTemplate, i + 1, subject);

        // Print Subject Key
        mbedtls_mpi_write_binary(&mbedtls_pk_rsa(crt_ctx->pk)->N, pubKey, sizeof(pubKey));
        printf(subjectKeyTemplate, pubKey[0], pubKey[1], pubKey[2], pubKey[3]);

        // Print FWID
        uint8_t *ext_addr;
        int ext_data_len;
        uint8_t fwid[SHA256_LEN];
        find_ext_by_oid(crt_ctx, dice_attestation_oid, sizeof(dice_attestation_oid), &ext_addr, &ext_data_len);
        if (ext_addr != NULL)
        {
            parse_attestation_extension(ext_addr, ext_data_len, fwid, sizeof(fwid));

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

static int verify_signatures(mbedtls_x509_crt *chain, mbedtls_x509_crt *root_crt)
{
    // From https://stackoverflow.com/a/72722115/2050020

    int res;
    uint32_t flags = 0;
    if ((res = mbedtls_x509_crt_verify(chain, root_crt, NULL, NULL, &flags,
                                       NULL, NULL)) != 0)
    {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("Verification of certificate signatures failed. Reason: %s\n", vrfy_buf);
        printf("Error: 0x%04x; flag: %u\n", res, flags);
    }
    else
        printf("Verification of certificate signatures OK\n");

    return res;
}

static int verify_tcis(mbedtls_x509_crt *chain)
{
    printf("\n");
    printf("Verification of trustworthiness of software chain (BLn -> fTPM).\n");
    printf("Note that the TCI of bl2 changes on each compilation.\n");
    printf("So, you might want to keep it untrusted during development, and set the TCI only once right before deployment.\n");
    for (int i = 0; chain != NULL; chain = chain->next, i++)
    {
        uint8_t *ext_addr;
        int ext_data_len;
        uint8_t fwid[SHA256_LEN];
        find_ext_by_oid(chain, dice_attestation_oid, sizeof(dice_attestation_oid), &ext_addr, &ext_data_len);
        if (ext_addr != NULL && chain_info[i].expected_tci != NULL)
        {
            parse_attestation_extension(ext_addr, ext_data_len, fwid, sizeof(fwid));

            printf("Checking trustworthiness of %-6s...", chain_info[i].name);
            if (memcmp(fwid, chain_info[i].expected_tci, sizeof(fwid)) == 0)
                printf(" Trusted\n");
            else
                printf(" Untrusted\n");
        }
    }
    return 0;
}

static void verifyDataSignature(uint8_t *data, size_t dataSize, uint8_t *signature, size_t signatureSize, mbedtls_pk_context *pk_ctx)
{
    // Get the message digest info structure for SHA256
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char *md = malloc(mdinfo->size);
    // Calculate the message digest for the data
    mbedtls_md(mdinfo, data, dataSize, md);

    printf("First four bytes of hash: %02x %02x %02x %02x\n", md[0], md[1], md[2], md[3]);

    // Now verify the signature for the given hash of the data
    int st = mbedtls_pk_verify(pk_ctx, 
                               mdinfo->type, md, mdinfo->size,
                               signature, signatureSize);

    // mbedtls_pk_rsassa_pss_options options;
    // options.mgf1_hash_id = MBEDTLS_MD_SHA256;
    // options.expected_salt_len = 0;
    // int st = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &options, pk_ctx, 
    //                         mdinfo->type, md, mdinfo->size,
    //                         signature, signatureSize);
    if (st != 0) {
        // Signature invalid!
        printf("Signature invalid!\n");
    } else {
        // Signature valid
        printf("Signature valid!\n");
    }

    free(md);
}

int main(void)
{
    // The certificates are stored here in DER format
    // For our certificates, they are always a bit smaller than 1000 bytes.
    // We expect a certificate chain of length 5.
    // So, give a 5 * 1000 bytes buffer
    uint8_t buffer_crts[5000];

    // first element is length of chain
    // Array size must be at least length of chain + 1
    uint16_t buffer_offsets[8];

    mbedtls_x509_crt crt_ctx, root_crt;
    mbedtls_x509_crt_init(&crt_ctx);
    mbedtls_x509_crt_init(&root_crt);

    int res = parse_crt_from_buffer(&root_crt, crt_manufacturer, sizeof(crt_manufacturer), "crt_manufacturer");
    if (res != 0)
        return res;


    uint8_t signature[256] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t nonce[] = "Hello world";
    invoke_ftpm_ta(buffer_crts, sizeof(buffer_crts),
                   buffer_offsets, sizeof(buffer_offsets),
                   signature, sizeof(signature),
                   nonce, sizeof(nonce));

    
    parse_buffers(buffer_crts, sizeof(buffer_crts),
                  buffer_offsets, sizeof(buffer_offsets), &crt_ctx);

    unsigned char *ekCert = GetEkCert(&crt_ctx)->pk_raw.p;
    printf("EK public key:\n");
    for (size_t x = 0; x < GetEkCert(&crt_ctx)->pk_raw.len; x += 8)
    {
        printf("%08lx: %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                    ekCert[x + 0], ekCert[x + 1], ekCert[x + 2], ekCert[x + 3],
                    ekCert[x + 4], ekCert[x + 5], ekCert[x + 6], ekCert[x + 7]);
    }

    verifyDataSignature(nonce, sizeof(nonce), signature, sizeof(signature), &GetEkCert(&crt_ctx)->pk);
    print_infos_of_certificates(&crt_ctx, &root_crt);
    write_certificates(&crt_ctx);
    verify_signatures(&crt_ctx, &root_crt);
    verify_tcis(&crt_ctx);
    mbedtls_x509_crt_free(&crt_ctx);
    mbedtls_x509_crt_free(&root_crt);

    return 0;
}
