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

#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#include "dds/security/dds_security_api.h"
#include "dds/ddsrt/time.h"


typedef enum {
    AUTHENTICATION_ALGO_KIND_UNKNOWN,
    AUTHENTICATION_ALGO_KIND_RSA_2048,
    AUTHENTICATION_ALGO_KIND_EC_PRIME256V1
} AuthenticationAlgoKind_t;

typedef enum {
    AUTH_CONF_ITEM_PREFIX_UNKNOWN,
    AUTH_CONF_ITEM_PREFIX_FILE,
    AUTH_CONF_ITEM_PREFIX_DATA,
    AUTH_CONF_ITEM_PREFIX_PKCS11
} AuthConfItemPrefix_t;


typedef struct AuthenticationChallenge {
    unsigned char value[DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE];
} AuthenticationChallenge;

typedef struct {
    DDS_Security_unsigned_long _length;
    X509 **_buffer;
} X509Seq;

typedef unsigned char HashValue_t[SHA256_DIGEST_LENGTH];

/* Return a string that contains an openssl error description
 * When a openssl function returns an error this function can be
 * used to retrieve a descriptive error string.
 * Note that the returned string should be freed.
 */
char *
get_openssl_error_message(
        void);

/* Return the subject name of contained in a X509 certificate
 *
 */
char*
get_certificate_subject_name(
        X509 *cert,
        DDS_Security_SecurityException *ex);

/* Return the expiry date of contained in a X509 certificate
 *
 */
dds_time_t
get_certificate_expiry(
    X509 *cert);

/* Return the subject name of a X509 certificate DER
 * encoded. The DER encoded subject name is returned in
 * the provided buffer. The length of the allocated
 * buffer is returned
 *
 * return length of allocated buffer or -1 on error
 */
int32_t
get_subject_name_DER_encoded(
        const X509 *cert,
        unsigned char **buffer,
        DDS_Security_SecurityException *ex);


/* Load a X509 certificate for the provided data.
 *
 * data     : certificate in PEM format
 * x509Cert : the openssl X509 return value
 */
DDS_Security_ValidationResult_t
load_X509_certificate_from_data(
        const char *data,
        int len,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex);


/* Load a X509 certificate for the provided data.
 *
 * data     : formatted string containing the certificate
 *            description
 * x509Cert : the openssl X509 return value
 */
DDS_Security_ValidationResult_t
load_X509_certificate(
        const char *data,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex);


/* Load a X509 certificate for the provided file.
 *
 * data     : formatted string containing the certificate
 *            file path
 * x509Cert : the openssl X509 return value
 */
DDS_Security_ValidationResult_t
load_X509_certificate_from_file(
        const char *filename,
        X509 **x509Cert,
        DDS_Security_SecurityException *ex);

/* Load a Private Key for the provided data.
 *
 * data       : formatted string containing the private key
 *              description
 * privateKey : the openssl EVP_PKEY return value
 */
DDS_Security_ValidationResult_t
load_X509_private_key(
        const char *data,
        const char *password,
        EVP_PKEY **privateKey,
        DDS_Security_SecurityException *ex);


/* Validate an identity certificate against the identityCA
 * The provided identity certificate is checked if it is
 * signed by the identity corresponding to the identityCA.
 *
 * Note: Currently only a self signed CA is supported
 *       The function does not yet check a CLR or ocsp
 *       for expiry of identity certificate.
 */
DDS_Security_ValidationResult_t
verify_certificate(
        X509 *identityCert,
        X509 *identityCa,
        DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
check_certificate_expiry(
    X509 *cert,
    DDS_Security_SecurityException *ex);

AuthenticationAlgoKind_t
get_auhentication_algo_kind(
        X509 *cert);

AuthenticationChallenge *
generate_challenge(
        DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
get_certificate_contents(
        X509 *cert,
        unsigned char **data,
				uint32_t *size,
        DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
generate_dh_keys(
    EVP_PKEY **dhkey,
    AuthenticationAlgoKind_t authKind,
    DDS_Security_SecurityException *ex);

#if 0
DDS_Security_ValidationResult_t
get_public_key(
    EVP_PKEY *pkey,
    unsigned char **buffer,
    uint32_t *length,
    DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
read_public_key(
    EVP_PKEY **pkey,
    const unsigned char *keystr,
    uint32_t size,
    DDS_Security_SecurityException *ex);
#endif

DDS_Security_ValidationResult_t
dh_get_public_key_value(
    EVP_PKEY *pkey,
    AuthenticationAlgoKind_t algo,
    unsigned char **buffer,
		uint32_t *length,
    DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
dh_read_public_key_by_value(
    EVP_PKEY **pkey,
    AuthenticationAlgoKind_t algo,
    const unsigned char *keystr,
		uint32_t size,
    DDS_Security_SecurityException *ex);


AuthConfItemPrefix_t
get_conf_item_type(
        const char *str,
        char **data);

void
clean_ca_list(
     X509Seq *ca_list);

DDS_Security_ValidationResult_t
get_trusted_ca_list (
    const char* trusted_ca_dir,
    X509Seq *ca_list,
    DDS_Security_SecurityException *ex);

char *
string_from_data(
    const unsigned char *data,
    uint32_t size);

DDS_Security_ValidationResult_t
create_asymmetrical_signature(
    EVP_PKEY *pkey,
    void *data,
		size_t dataLen,
    unsigned char **signature,
		size_t *signatureLen,
    DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
validate_asymmetrical_signature(
    EVP_PKEY *pkey,
    void *data,
		size_t dataLen,
    unsigned char *signature,
		size_t signatureLen,
    DDS_Security_SecurityException *ex);

#endif /* AUTH_UTILS_H */
