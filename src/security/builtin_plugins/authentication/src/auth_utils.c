/*
 *                         Vortex OpenSplice
 *
 *   This software and documentation are Copyright 2006 to TO_YEAR ADLINK
 *   Technology Limited, its affiliated companies and licensors. All rights
 *   reserved.
 *
 *   Licensed under the ADLINK Software License Agreement Rev 2.7 2nd October
 *   2014 (the "License"); you may not use this file except in compliance with
 *   the License.
 *   You may obtain a copy of the License at:
 *                      $OSPL_HOME/LICENSE
 *
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
#define AUTH_INCLUDE_EC
#include <openssl/ec.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define AUTH_INCLUDE_DH_ACCESSORS
#endif
#else
#error "version not found"
#endif
#include <openssl/rand.h>
#include "stdlib.h"
#include "dds/ddsrt/time.h"
#include "dds/ddsrt/heap.h"
#include "dds/security/dds_security_api_defs.h"
#include "assert.h"


/* There is a problem when compiling on windows w.r.t. X509_NAME.
 * The windows api already defines the type X509_NAME which
 * conficts with some openssl versions. The workaround is to
 * undef the openssl X509_NAME
 */
#ifdef OSPL_UNDEF_X509_NAME
#undef X509_NAME
#endif

#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/string.h"
#include "dds/security/core/dds_security_utils.h"
#include <string.h>
#include "auth_defs.h"
#include "auth_utils.h"


#define MAX_TRUSTED_CA 100

char *
get_openssl_error_message(
        void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *msg;
    char *buf = NULL;
    size_t len; /*BIO_get_mem_data requires long int */

    if (bio) {
        ERR_print_errors(bio);
        len = (size_t)BIO_get_mem_data (bio, &buf);
        msg = ddsrt_malloc(len + 1);
        memset(msg, 0, len+1);
        memcpy(msg, buf, len);
        BIO_free(bio);
    } else {
        msg = ddsrt_strdup("BIO_new failed");
    }

    return msg;
}

char *
get_certificate_subject_name(
        X509 *cert,
        DDS_Security_SecurityException *ex)
{
    X509_NAME *name;
    BIO *bio;
    char *subject = NULL;
    char *pmem;
    size_t sz;

    assert(cert);

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
        goto err_bio_alloc;
    }

    name = X509_get_subject_name(cert);
    if (!name) {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "X509_get_subject_name failed : %s", msg);
        ddsrt_free(msg);
        goto err_get_subject;
    }

    /* TODO: check if this is the correct format of the subject name: check spec */
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);

    sz = (size_t)BIO_get_mem_data(bio, &pmem);
    subject = ddsrt_malloc( sz + 1);

    if (BIO_gets(bio, subject, (int32_t)sz + 1) < 0) {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "X509_get_subject_name failed : %s", msg);
        ddsrt_free(msg);
        ddsrt_free(subject);
        subject = NULL;
    }

    BIO_free(bio);

    return subject;

err_get_subject:
    BIO_free(bio);
err_bio_alloc:
    return NULL;
}

dds_time_t
get_certificate_expiry(
    X509 *cert)
{
    dds_time_t expiry = DDS_TIME_INVALID;
    ASN1_TIME *ans1;

    assert(cert);

    ans1 = X509_get_notAfter(cert);
    if (ans1 != NULL) {
        int days;
        int seconds;
        if (ASN1_TIME_diff(&days, &seconds, NULL, ans1) != 0) {
            static const dds_duration_t secs_per_day = 86400;
            dds_duration_t delta = ((dds_duration_t)seconds + ((dds_duration_t)days * secs_per_day)) * DDS_NSECS_IN_SEC;
            expiry = dds_time() + delta;
        }
    }

    return expiry;
}

int32_t
get_subject_name_DER_encoded(
        const X509 *cert,
        unsigned char **buffer,
        DDS_Security_SecurityException *ex)
{
    X509_NAME *name;
    unsigned char *tmp = NULL;
    int32_t sz = -1;

    assert(cert);
    assert(buffer);

    name = X509_get_subject_name((X509 *)cert);
    if (name) {
        sz = i2d_X509_NAME(name, &tmp);
        if (sz > 0) {
            *buffer = ddsrt_malloc((size_t)sz);
            memcpy(*buffer, tmp, (size_t)sz);
            OPENSSL_free(tmp);
        } else if (sz < 0) {
            char *msg = get_openssl_error_message();
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "i2d_X509_NAME failed : %s", msg);
            ddsrt_free(msg);
        }
    } else {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED, "X509_get_subject_name failed : %s", msg);
        ddsrt_free(msg);
    }

    return sz;
}


static DDS_Security_ValidationResult_t
check_key_type_and_size(
    EVP_PKEY *key,
    int isPrivate,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    const char *sub = isPrivate ? "private key" : "certificate";

    assert(key);

    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        if (EVP_PKEY_bits(key) != 2048) {
            result = DDS_SECURITY_VALIDATION_FAILED;
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "RSA %s has unsupported key size (%d)", sub, EVP_PKEY_bits(key));
        } else if (isPrivate) {
            RSA *rsaKey = EVP_PKEY_get1_RSA(key);
            if (rsaKey) {
                if (RSA_check_key(rsaKey) != 1) {
                    char *msg = get_openssl_error_message();
                    result = DDS_SECURITY_VALIDATION_FAILED;
                    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "RSA key not correct : %s", msg);
                    ddsrt_free(msg);
                }
            }
            RSA_free(rsaKey);
        }
        break;
    case EVP_PKEY_EC:
        if (EVP_PKEY_bits(key) != 256) {
            result = DDS_SECURITY_VALIDATION_FAILED;
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "EC %s has unsupported key size (%d)", sub, EVP_PKEY_bits(key));
        } else {
            EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(key);
            if (ecKey) {
                if (EC_KEY_check_key(ecKey) != 1) {
                    char *msg = get_openssl_error_message();
                    result = DDS_SECURITY_VALIDATION_FAILED;
                    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "EC key not correct : %s", msg);
                    ddsrt_free(msg);
                }
            }
            EC_KEY_free(ecKey);
        }
        break;
    default:
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "%s has not supported type", sub);
        break;
    }

    return result;
}

static DDS_Security_ValidationResult_t
check_certificate_type_and_size(
    X509 *cert,
    DDS_Security_SecurityException *ex)
{
    EVP_PKEY *pkey;
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;

    assert(cert);

    pkey = X509_get_pubkey(cert);
    if (pkey) {
        result = check_key_type_and_size(pkey, false, ex);
    } else {
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "X509_get_pubkey failed");
    }
    EVP_PKEY_free(pkey);

    return result;
}

DDS_Security_ValidationResult_t
check_certificate_expiry(
    X509 *cert,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;

    assert(cert);

    if( X509_cmp_current_time(X509_get_notBefore( cert )) == 0 ){
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_STARTDATE_INVALID_CODE, result, DDS_SECURITY_ERR_CERT_STARTDATE_INVALID_MESSAGE);

    }
    if( X509_cmp_current_time(X509_get_notAfter( cert )) == 0 ){
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_EXPIRED_CODE, result, DDS_SECURITY_ERR_CERT_STARTDATE_INVALID_MESSAGE);

    }

    return result;
}


DDS_Security_ValidationResult_t
load_X509_certificate_from_data(
        const char *data,
        int len,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    BIO *bio;

    assert(data);
    assert(len >= 0);
    assert(x509Cert);

    /* load certificate in buffer */
    bio = BIO_new_mem_buf((void *) data, len);
    if (!bio) {
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "BIO_new_mem_buf failed");
        goto err_bio_alloc;
    }

    *x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!(*x509Cert)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to parse certificate: %s", msg);
        ddsrt_free(msg);
        goto err_cert_read;
    }

err_cert_read:
    BIO_free(bio);
err_bio_alloc:
    return result;
}



DDS_Security_ValidationResult_t
load_X509_certificate_from_file(
        const char *filename,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    FILE *file_ptr;

    assert(filename);
    assert(x509Cert);

    /*check the file*/
    file_ptr = fopen( filename, "r");

    if( file_ptr == NULL ){
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE, result, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filename);
        goto err_invalid_path;
    }

    /*load certificate from file*/
    *x509Cert = PEM_read_X509(file_ptr,NULL,NULL,NULL);
    if (!(*x509Cert)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to parse certificate: %s", msg);
        ddsrt_free(msg);
        goto err_invalid_content;
    }

    /* check authentication algorithm */
    if( get_auhentication_algo_kind( *x509Cert ) == AUTHENTICATION_ALGO_KIND_UNKNOWN ){
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_AUTHENTICATION_ALGO_KIND_UNKNOWN_CODE, result,
                        DDS_SECURITY_ERR_CERT_AUTHENTICATION_ALGO_KIND_UNKNOWN_MESSAGE);
        goto err_invalid_content;
    }


err_invalid_content:
    (void)fclose( file_ptr );
err_invalid_path:

    return result;
}

static DDS_Security_ValidationResult_t
load_private_key_from_data(
        const char *data,
        const char *password,
        EVP_PKEY **privateKey,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    BIO *bio;
    const char *pw = (password ? password : "");

    assert(data);
    assert(privateKey);

    /* load certificate in buffer */
    bio = BIO_new_mem_buf((void *) data, -1);
    if (!bio) {
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "BIO_new_mem_buf failed");
        goto err_bio_alloc;
    }

    *privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)pw);
    if (!(*privateKey)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to parse private key: %s", msg);
        ddsrt_free(msg);
        goto err_key_read;
    }

err_key_read:
    BIO_free(bio);
err_bio_alloc:
    return result;
}


static DDS_Security_ValidationResult_t
load_private_key_from_file(
        const char *filepath,
        const char *password,
        EVP_PKEY **privateKey,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    const char *pw = (password ? password : "");
    FILE *file_ptr;

    assert(filepath);
    assert(privateKey);

    /*check the file*/
    file_ptr = fopen( filepath, "r");

    if( file_ptr == NULL ){
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE, result, DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filepath);
        goto err_invalid_path;
    }

    /*load private key from file*/
    *privateKey = PEM_read_PrivateKey(file_ptr, NULL, NULL, (void *)pw);
    if (!(*privateKey)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to parse certificate: %s", msg);
        ddsrt_free(msg);
        goto err_invalid_content;
    }

err_invalid_content:
    (void)fclose( file_ptr );
err_invalid_path:

    return result;
}

static char *
strchrs (
    const char *str,
    const char *chrs,
    bool inc)
{
    bool eq;
    char *ptr = NULL;
    size_t i, j;

    assert (str != NULL);
    assert (chrs != NULL);

    for (i = 0; str[i] != '\0' && ptr == NULL; i++) {
        for (j = 0, eq = false; chrs[j] != '\0' && eq == false; j++) {
            if (str[i] == chrs[j]) {
                eq = true;
            }
        }
        if (eq == inc) {
            ptr = (char *)str + i;
        }
    }

    return ptr;
}


AuthConfItemPrefix_t
get_conf_item_type(
        const char *str,
        char **data)
{
    AuthConfItemPrefix_t kind = AUTH_CONF_ITEM_PREFIX_UNKNOWN;
    const char *AUTH_CONF_FILE_PREFIX    = "file:";
    const char *AUTH_CONF_DATA_PREFIX   = "data:,";
    const char *AUTH_CONF_PKCS11_PREFIX = "pkcs11:";
    size_t AUTH_CONF_FILE_PREFIX_LEN    = strlen(AUTH_CONF_FILE_PREFIX);
    size_t AUTH_CONF_DATA_PREFIX_LEN   = strlen(AUTH_CONF_DATA_PREFIX);
    size_t AUTH_CONF_PKCS11_PREFIX_LEN = strlen(AUTH_CONF_PKCS11_PREFIX);
    char *ptr;

    assert(str);
    assert(data);

    ptr = strchrs(str, " \t", false);

    if (strncmp(ptr, AUTH_CONF_FILE_PREFIX, AUTH_CONF_FILE_PREFIX_LEN) == 0) {
        const char *DOUBLE_SLASH   = "//";
        size_t DOUBLE_SLASH_LEN = 2;
        if (strncmp(&(ptr[AUTH_CONF_FILE_PREFIX_LEN]), DOUBLE_SLASH, DOUBLE_SLASH_LEN) == 0) {
            *data = ddsrt_strdup(&(ptr[AUTH_CONF_FILE_PREFIX_LEN + DOUBLE_SLASH_LEN]));
        } else {
            *data = ddsrt_strdup(&(ptr[AUTH_CONF_FILE_PREFIX_LEN]));
        }
        kind = AUTH_CONF_ITEM_PREFIX_FILE;
    } else if (strncmp(ptr, AUTH_CONF_DATA_PREFIX, AUTH_CONF_DATA_PREFIX_LEN) == 0) {
        kind = AUTH_CONF_ITEM_PREFIX_DATA;
        *data = ddsrt_strdup(&(ptr[AUTH_CONF_DATA_PREFIX_LEN]));
    } else if (strncmp(ptr, AUTH_CONF_PKCS11_PREFIX, AUTH_CONF_PKCS11_PREFIX_LEN) == 0) {
        kind = AUTH_CONF_ITEM_PREFIX_PKCS11;
        *data = ddsrt_strdup(&(ptr[AUTH_CONF_PKCS11_PREFIX_LEN]));
    }

    return kind;
}

DDS_Security_ValidationResult_t
load_X509_certificate(
        const char *data,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    char *contents = NULL;

    assert(data);
    assert(x509Cert);

    switch (get_conf_item_type(data, &contents)) {
    case AUTH_CONF_ITEM_PREFIX_FILE:
        result = load_X509_certificate_from_file(contents, x509Cert, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_DATA:
        result = load_X509_certificate_from_data(contents, (int)strlen(contents), x509Cert, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_PKCS11:
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Certificate pkcs11 format currently not supported:\n%s", data);
        break;
    default:
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Specified certificate has wrong format:\n%s", data);
        break;
    }
    ddsrt_free(contents);

    if (result == DDS_SECURITY_VALIDATION_OK) {
        if ( check_certificate_type_and_size(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK ||
             check_certificate_expiry(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK
                        ) {
            result = DDS_SECURITY_VALIDATION_FAILED;
            X509_free(*x509Cert);
        }
    }
    return result;
}

DDS_Security_ValidationResult_t
load_X509_private_key(
        const char *data,
        const char *password,
        EVP_PKEY **privateKey,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    char *contents = NULL;

    assert(data);
    assert(privateKey);

    switch (get_conf_item_type(data, &contents)) {
    case AUTH_CONF_ITEM_PREFIX_FILE:
        result = load_private_key_from_file(contents, password, privateKey, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_DATA:
        result = load_private_key_from_data(contents, password, privateKey, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_PKCS11:
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "PrivateKey pkcs11 format currently not supported:\n%s", data);
        break;
    default:
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Specified PrivateKey has wrong format:\n%s", data);
        break;
    }
    ddsrt_free(contents);

    if (result == DDS_SECURITY_VALIDATION_OK) {
        if ((result = check_key_type_and_size(*privateKey, true, ex)) != DDS_SECURITY_VALIDATION_OK) {
            EVP_PKEY_free(*privateKey);
        }
    }

    return result;
}

DDS_Security_ValidationResult_t
verify_certificate(
        X509 *identityCert,
        X509 *identityCa,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    int r;
    X509_STORE *store;
    X509_STORE_CTX *ctx;



    assert(identityCert);
    assert(identityCa);

    /* Currently only a self signed indentiyCa is supported */
    /* Verification of against a certificate chain is not yet supported */
    /* Verification of the certificate expiry using a CRL is not yet supported */

    store = X509_STORE_new();


    if (!store) {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "X509_STORE_new failed : %s", msg);
        ddsrt_free(msg);
        goto err_store_new;
    }

    if (X509_STORE_add_cert(store, identityCa) != 1) {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "X509_STORE_add_cert failed : %s", msg);
        ddsrt_free(msg);
        goto err_add_cert;
    }

    ctx = X509_STORE_CTX_new();
    if (!ctx) {
         char *msg = get_openssl_error_message();
         DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "X509_STORE_CTX_new failed : %s", msg);
         ddsrt_free(msg);
         goto err_ctx_new;
    }

    if (X509_STORE_CTX_init(ctx, store, identityCert, NULL) != 1) {
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "X509_STORE_CTX_init failed : %s", msg);
        ddsrt_free(msg);
        goto err_ctx_init;
    }

    r = X509_verify_cert(ctx);
    if (r != 1) {
        const char *msg = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
        char *subject = NULL;

        result = DDS_SECURITY_VALIDATION_FAILED;
        subject = get_certificate_subject_name(identityCert, NULL);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result,
                "Certificate not valid: error: %s subject: %s", msg, subject ? subject : "not found");
        ddsrt_free(subject);
    }

err_ctx_init:
    X509_STORE_CTX_free(ctx);
err_ctx_new:
err_add_cert:
    X509_STORE_free(store);
err_store_new:
    return result;
}

AuthenticationAlgoKind_t
get_auhentication_algo_kind(
        X509 *cert)
{
    AuthenticationAlgoKind_t kind = AUTHENTICATION_ALGO_KIND_UNKNOWN;
    EVP_PKEY *pkey;

    assert(cert);

    pkey = X509_get_pubkey(cert);

    if (pkey) {
        switch (EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
             if (EVP_PKEY_bits(pkey) == 2048) {
                 kind = AUTHENTICATION_ALGO_KIND_RSA_2048;
             }
        break;
        case EVP_PKEY_EC:
            if (EVP_PKEY_bits(pkey) == 256) {
                kind = AUTHENTICATION_ALGO_KIND_EC_PRIME256V1;
            }
            break;
        default:
        break;
        }
        EVP_PKEY_free(pkey);
    }

    return kind;
}

AuthenticationChallenge *
generate_challenge(
        DDS_Security_SecurityException *ex)
{
    AuthenticationChallenge *result;

    result = ddsrt_malloc(sizeof(*result));
    if (RAND_bytes(result->value, sizeof(result->value)) < 0 ) {
        char *msg = get_openssl_error_message();

        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED,
                "Failed to generate a 256 bit random number %s", msg);
        ddsrt_free(msg);
        ddsrt_free(result);
        result = NULL;
    }

    return result;
}

DDS_Security_ValidationResult_t
get_certificate_contents(
        X509 *cert,
        unsigned char **data,
				uint32_t *size,
        DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    BIO *bio = NULL;
    size_t sz;
    char *ptr;

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result, "BIO_new_mem_buf failed");
    } else if (!PEM_write_bio_X509(bio, cert)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result, "PEM_write_bio_X509 failed: %s", msg);
        ddsrt_free(msg);
    } else {
        sz = (size_t)BIO_get_mem_data(bio, &ptr);
        *data = ddsrt_malloc(sz +1);
        memcpy(*data, ptr, sz);
        (*data)[sz] = '\0';
        *size = (uint32_t)sz;
    }

    if (bio) BIO_free(bio);

    return result;
}

static DDS_Security_ValidationResult_t
get_rsa_dh_parameters(
    EVP_PKEY **params,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    DH *dh = NULL;

    *params = NULL;

    if ((*params = EVP_PKEY_new()) == NULL) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to allocate DH generation parameters: %s", msg);
        ddsrt_free(msg);
    } else if ((dh = DH_get_2048_256()) == NULL) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to allocate DH parameter using DH_get_2048_256: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_set1_DH(*params, dh) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to set DH generation parameters using EVP_PKEY_set1_DH: %s", msg);
        ddsrt_free(msg);
        EVP_PKEY_free(*params);
    }
    /* for printing the params and check
    {
        DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
        BIO *bio = BIO_new(BIO_s_mem());
        char *ptr = NULL;
        int sz;
        unsigned char * buffer;

        if ((bio = BIO_new(BIO_s_mem())) == NULL) {
          result = DDS_SECURITY_VALIDATION_FAILED;
          DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result, "Failed to get public key: BIO_new_mem_buf failed");
        } else if (!PEM_write_bio_Parameters(bio, *params)) {
          char *msg = get_openssl_error_message();
          result = DDS_SECURITY_VALIDATION_FAILED;
          DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result, "Failed to get public key: PEM_write_bio_PUBKEY failed: %s", msg);
          ddsrt_free(msg);
        } else {
          sz = BIO_get_mem_data(bio, &ptr);
          printf("DH PArams: %s\n", ptr);
        }

        if (bio) BIO_free(bio);
    } */

    if (dh) DH_free(dh);

    return result;
}

static DDS_Security_ValidationResult_t
get_ec_dh_parameters(
    EVP_PKEY **params,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    EVP_PKEY_CTX *pctx = NULL;

    if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to allocate DH parameter context: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to initialize DH generation context: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to set DH generation parameter generation method: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_paramgen(pctx, params) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to generate DH parameters: %s", msg);
        ddsrt_free(msg);
    }

    if (pctx) EVP_PKEY_CTX_free(pctx);

    return result;
}


DDS_Security_ValidationResult_t
generate_dh_keys(
    EVP_PKEY **dhkey,
    AuthenticationAlgoKind_t authKind,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_FAILED;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    *dhkey = NULL;

    switch(authKind) {
    case AUTHENTICATION_ALGO_KIND_RSA_2048:
        result = get_rsa_dh_parameters(&params, ex);
        break;
    case AUTHENTICATION_ALGO_KIND_EC_PRIME256V1:
        result = get_ec_dh_parameters(&params, ex);
        break;
    default:
        assert(0);
        break;
    }

    if (result != DDS_SECURITY_VALIDATION_OK) {
        return result;
    } else if ((kctx = EVP_PKEY_CTX_new(params, NULL)) == NULL) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to allocate DH generation context: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_keygen_init(kctx) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to initialize DH generation context: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_keygen(kctx, dhkey) <= 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,  result,
                "Failed to generate DH key pair: %s", msg);
        ddsrt_free(msg);
    }

    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (params) EVP_PKEY_free(params);

    return result;
}

static const BIGNUM *
dh_get_public_key(
    DH *dhkey)
{
#ifdef AUTH_INCLUDE_DH_ACCESSORS
    const BIGNUM *pubkey, *privkey;
    DH_get0_key(dhkey, &pubkey, &privkey);
    return pubkey;
#else
    return dhkey->pub_key;
#endif
}

static int
dh_set_public_key(
    DH *dhkey,
    BIGNUM *pubkey)
{
#ifdef AUTH_INCLUDE_DH_ACCESSORS
    return DH_set0_key(dhkey, pubkey, NULL);
#else
    dhkey->pub_key = pubkey;
#endif
    return 1;
}

static DDS_Security_ValidationResult_t
dh_public_key_to_oct_modp(
    EVP_PKEY *pkey,
    unsigned char **buffer,
    uint32_t *length,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    DH *dhkey;
    ASN1_INTEGER *asn1int;

    *buffer = NULL;

    dhkey = EVP_PKEY_get1_DH(pkey);
    if (!dhkey) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to get DH key from PKEY: %s", msg);
        ddsrt_free(msg);
        goto fail_get_dhkey;
    }

    asn1int = BN_to_ASN1_INTEGER(dh_get_public_key(dhkey), NULL);
    if (!asn1int) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert DH key to ASN1 integer: %s", msg);
        ddsrt_free(msg);
        goto fail_get_asn1int;
    }

    *length = (uint32_t) i2d_ASN1_INTEGER(asn1int, buffer);

    ASN1_INTEGER_free(asn1int);

fail_get_asn1int:
    DH_free(dhkey);
fail_get_dhkey:
    return result;
}

static DDS_Security_ValidationResult_t
dh_public_key_to_oct_ecdh(
    EVP_PKEY *pkey,
    unsigned char **buffer,
    uint32_t *length,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    EC_KEY *eckey;
    const EC_GROUP *group;
    const EC_POINT *point;
    size_t sz;

    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to get EC key from PKEY: %s", msg);
        ddsrt_free(msg);
        goto fail_get_eckey;
    }

    point = EC_KEY_get0_public_key(eckey);
    if (!point) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to get public key from ECKEY: %s", msg);
        ddsrt_free(msg);
        goto fail_get_point;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to get group from ECKEY: %s", msg);
        ddsrt_free(msg);
        goto fail_get_group;
    }

    sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (sz == 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to serialize public EC key: %s", msg);
        ddsrt_free(msg);
        goto fail_point2oct1;
    }

    *buffer = ddsrt_malloc(sz);

    *length = (uint32_t)EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, *buffer, sz, NULL);
    if (*length == 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to serialize public EC key: %s", msg);
        ddsrt_free(msg);
        goto fail_point2oct2;
    }

    EC_KEY_free(eckey);

    return result;

fail_point2oct2:
    ddsrt_free(*buffer);
fail_point2oct1:
fail_get_group:
fail_get_point:
fail_get_eckey:
    EC_KEY_free(eckey);
    return result;
}

DDS_Security_ValidationResult_t
dh_get_public_key_value(
    EVP_PKEY *pkey,
    AuthenticationAlgoKind_t algo,
    unsigned char **buffer,
		uint32_t *length,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;

    assert(pkey);
    assert(buffer);
    assert(length);

    switch (algo) {
    case AUTHENTICATION_ALGO_KIND_RSA_2048:
        result = dh_public_key_to_oct_modp(pkey, buffer, length, ex);
        break;
    case AUTHENTICATION_ALGO_KIND_EC_PRIME256V1:
        result = dh_public_key_to_oct_ecdh(pkey, buffer, length, ex);
        break;
    default:
        assert(0);
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Invalid key algorithm specified");
        break;
    }

    return result;
}

static DDS_Security_ValidationResult_t
dh_oct_to_public_key_modp(
    EVP_PKEY **pkey,
    const unsigned char *keystr,
    uint32_t size,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    DH *dhkey;
    ASN1_INTEGER *asn1int;
    BIGNUM *pubkey;

    *pkey = EVP_PKEY_new();
    if (!(*pkey)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert octet sequence to ASN1 integer: %s", msg);
        ddsrt_free(msg);
        goto fail_alloc_pkey;
    }

    asn1int = d2i_ASN1_INTEGER(NULL, (const unsigned char **)&keystr, size);
    if (!asn1int) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert octet sequence to ASN1 integer: %s", msg);
        ddsrt_free(msg);
        goto fail_get_asn1int;
    }

    pubkey = ASN1_INTEGER_to_BN(asn1int, NULL);
    if (!pubkey) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert ASN1 integer to BIGNUM: %s", msg);
        ddsrt_free(msg);
        goto fail_get_pubkey;
    }

    dhkey = DH_get_2048_256();

    if (dh_set_public_key(dhkey, pubkey) == 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to set DH public key: %s", msg);
        ddsrt_free(msg);
    } else if (EVP_PKEY_set1_DH(*pkey, dhkey) == 0) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert DH to PKEY: %s", msg);
        ddsrt_free(msg);
    }

    ASN1_INTEGER_free(asn1int);
    DH_free(dhkey);

    return result;

fail_get_pubkey:
    ASN1_INTEGER_free(asn1int);
fail_get_asn1int:
    EVP_PKEY_free(*pkey);
fail_alloc_pkey:
    return result;
}

static DDS_Security_ValidationResult_t
dh_oct_to_public_key_ecdh(
    EVP_PKEY **pkey,
    const unsigned char *keystr,
    uint32_t size,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    EC_KEY *eckey;
    EC_GROUP *group;
    EC_POINT *point;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to allocate EC group: %s", msg);
        ddsrt_free(msg);
        goto fail_alloc_group;
    }

    point = EC_POINT_new(group);
    if (!point) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to allocate EC point: %s", msg);
        ddsrt_free(msg);
        goto fail_alloc_point;
    }


    if (EC_POINT_oct2point(group, point, keystr, size, NULL) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to deserialize EC public key to EC point: %s", msg);
        ddsrt_free(msg);
        goto fail_oct2point;
    }

    eckey = EC_KEY_new();
    if (!eckey) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to allocate EC KEY: %s", msg);
        ddsrt_free(msg);
        goto fail_alloc_eckey;
    }

    if (EC_KEY_set_group(eckey, group) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to convert octet sequence to ASN1 integer: %s", msg);
        ddsrt_free(msg);
        goto fail_eckey_set_group;
    }

    if (EC_KEY_set_public_key(eckey, point) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to set EC public key: %s", msg);
        ddsrt_free(msg);
        goto fail_eckey_set_pubkey;
    }

    *pkey = EVP_PKEY_new();
    if (!(*pkey)) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to allocate EVP key: %s", msg);
        ddsrt_free(msg);
        goto fail_alloc_pkey;
    }

    if (EVP_PKEY_set1_EC_KEY(*pkey, eckey) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to set EVP key to EC public key: %s", msg);
        ddsrt_free(msg);
        goto fail_pkey_set_eckey;
    }

    EC_KEY_free(eckey);
    EC_POINT_free(point);
    EC_GROUP_free(group);

    return result;

fail_pkey_set_eckey:
    EVP_PKEY_free(*pkey);
fail_alloc_pkey:
fail_eckey_set_pubkey:
fail_eckey_set_group:
    EC_KEY_free(eckey);
fail_alloc_eckey:
fail_oct2point:
    EC_POINT_free(point);
fail_alloc_point:
    EC_GROUP_free(group);
fail_alloc_group:
    return result;
}

DDS_Security_ValidationResult_t
dh_read_public_key_by_value(
    EVP_PKEY **pkey,
    AuthenticationAlgoKind_t algo,
    const unsigned char *keystr,
		uint32_t size,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;

    assert(pkey);
    assert(keystr);

    switch (algo) {
    case AUTHENTICATION_ALGO_KIND_RSA_2048:
        result = dh_oct_to_public_key_modp(pkey, keystr, size, ex);
        break;
    case AUTHENTICATION_ALGO_KIND_EC_PRIME256V1:
        result = dh_oct_to_public_key_ecdh(pkey, keystr, size, ex);
        break;
    default:
        assert(0);
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Invalid key algorithm specified");
        break;
    }

    return result;
}

char *
string_from_data(
    const unsigned char *data,
    uint32_t size)
{
    char *str = NULL;

    if (size > 0 && data) {
        str = ddsrt_malloc(size+1);
        memcpy(str, data, size);
        str[size] = '\0';
    }

    return str;
}

void
clean_ca_list( X509Seq *ca_list)
{
    unsigned i;
    if( ca_list->_buffer != NULL && ca_list->_length > 0){
        for (i = 0; i < ca_list->_length; ++i) {
            X509_free(ca_list->_buffer[i]);
        }
        ddsrt_free ( ca_list->_buffer );
    }
    ca_list->_buffer = NULL;
    ca_list->_length = 0;
}

DDS_Security_ValidationResult_t
get_trusted_ca_list ( const char* trusted_ca_dir,
                X509Seq *ca_list,
                DDS_Security_SecurityException *ex){


    DDS_Security_ValidationResult_t loading_result = DDS_SECURITY_VALIDATION_OK;
    DDSRT_UNUSED_ARG( ca_list );
    DDSRT_UNUSED_ARG( trusted_ca_dir );
    DDSRT_UNUSED_ARG( ex );
/* TODO: Trusted CA directory tracing function should be ported */
#if( 0 )

    os_result        r;
    os_dirHandle     d_descr;
    struct os_dirent d_entry;
    struct os_stat_s status;
    char *full_file_path;
    char *trusted_ca_dir_normalized;

    X509 *ca_buffer_array[MAX_TRUSTED_CA]; /*max trusted CA size */
    unsigned ca_buffer_array_size=0;
    unsigned i;
    trusted_ca_dir_normalized  = os_fileNormalize(trusted_ca_dir);

    r = os_opendir(trusted_ca_dir_normalized, &d_descr);
    ddsrt_free ( trusted_ca_dir_normalized );

    if (r == os_resultSuccess && ca_buffer_array_size < MAX_TRUSTED_CA) { /* accessable */
        r = os_readdir(d_descr, &d_entry);
        while (r == os_resultSuccess) {
            full_file_path = (char*) ddsrt_malloc(strlen(trusted_ca_dir) + strlen(os_fileSep()) + strlen(d_entry.d_name) + strlen(os_fileSep()) + 1 );
            ddsrt_strcpy(full_file_path, trusted_ca_dir);
            ddsrt_strcat(full_file_path, os_fileSep());
            ddsrt_strcat(full_file_path, d_entry.d_name);

            if (os_stat (full_file_path, &status) == os_resultSuccess) { /* accessable */
                if ((strcmp(d_entry.d_name, ".") != 0) &&
                    (strcmp(d_entry.d_name, "..") != 0)) {
                    char * filename = os_fileNormalize(full_file_path);

                    if(filename){
                        X509 *identityCA;
                        loading_result = load_X509_certificate_from_file( filename, &identityCA, ex);

                        ddsrt_free(filename);

                        if( loading_result == DDS_SECURITY_VALIDATION_OK ){
                            ca_buffer_array[ca_buffer_array_size] = identityCA;
                            ca_buffer_array_size++;

                        }
                    }
                }
            }
            r = os_readdir(d_descr, &d_entry);

            ddsrt_free(full_file_path);
        }

        os_closedir (d_descr);

        /* deallocate given ca_list if it is not NULL */
        clean_ca_list(ca_list);

        /*copy CAs to out parameter as HASH*/
        if( ca_buffer_array_size > 0 ){
            ca_list->_buffer = ddsrt_malloc( ca_buffer_array_size * sizeof(X509 * ) );
            for (i = 0; i < ca_buffer_array_size; ++i) {
                ca_list->_buffer[i] = ca_buffer_array[i];

            }

        }
        ca_list->_length = ca_buffer_array_size;

        return DDS_SECURITY_VALIDATION_OK;

    }
    else{
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_CODE, 0, DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_MESSAGE);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
#endif

    return loading_result;
}

DDS_Security_ValidationResult_t
create_asymmetrical_signature(
    EVP_PKEY *pkey,
    void *data,
		size_t dataLen,
    unsigned char **signature,
		size_t *signatureLen,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    if (!(mdctx = EVP_MD_CTX_create())) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to create signing context: %s", msg);
        ddsrt_free(msg);
        goto err_create_ctx;
    }

    if (EVP_DigestSignInit(mdctx, &kctx, EVP_sha256(), NULL, pkey) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to initialize signing context: %s", msg);
        ddsrt_free(msg);
        goto err_sign;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(kctx, RSA_PKCS1_PSS_PADDING) < 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to initialize signing context: %s", msg);
        ddsrt_free(msg);
        goto err_sign;
    }

    if (EVP_DigestSignUpdate(mdctx, data, dataLen) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to update signing context: %s", msg);
        ddsrt_free(msg);
        goto err_sign;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, signatureLen) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to finalize signing context: %s", msg);
        ddsrt_free(msg);
        goto err_sign;
    }

    *signature = ddsrt_malloc(sizeof(unsigned char) * (*signatureLen));
    assert(*signature != NULL);
    if (EVP_DigestSignFinal(mdctx, *signature, signatureLen) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to finalize signing context: %s", msg);
        ddsrt_free(msg);
        ddsrt_free(*signature);
    }

err_sign:
    EVP_MD_CTX_destroy(mdctx);
err_create_ctx:
    return result;
}

DDS_Security_ValidationResult_t
validate_asymmetrical_signature(
    EVP_PKEY *pkey,
    void *data,
		size_t dataLen,
    unsigned char *signature,
		size_t signatureLen,
    DDS_Security_SecurityException *ex)
{
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_OK;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    if (!(mdctx = EVP_MD_CTX_create())) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to create verify context: %s", msg);
        ddsrt_free(msg);
        goto err_create_ctx;
    }

    if (EVP_DigestVerifyInit(mdctx, &kctx, EVP_sha256(), NULL, pkey) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to initialize verify context: %s", msg);
        ddsrt_free(msg);
        goto err_verify;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(kctx, RSA_PKCS1_PSS_PADDING) < 1) {
         char *msg = get_openssl_error_message();
         result = DDS_SECURITY_VALIDATION_FAILED;
         DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to initialize signing context: %s", msg);
         ddsrt_free(msg);
         goto err_verify;
     }

    if (EVP_DigestVerifyUpdate(mdctx, data, dataLen) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to update verify context: %s", msg);
        ddsrt_free(msg);
        goto err_verify;
    }

    if (EVP_DigestVerifyFinal(mdctx, signature, signatureLen) != 1) {
        char *msg = get_openssl_error_message();
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, result, "Failed to finalize verify context: %s", msg);
        ddsrt_free(msg);
        goto err_verify;
    }

err_verify:
    EVP_MD_CTX_destroy(mdctx);
err_create_ctx:
    return result;
}
