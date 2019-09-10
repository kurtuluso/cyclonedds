/*
 * shared_secret_handle.h
 *
 *  Created on: May 9, 2018
 *      Author: kurtulus
 */


#ifndef SRC_SECURITY_CORE_INCLUDE_SHARED_SECRET_HANDLE_H_
#define SRC_SECURITY_CORE_INCLUDE_SHARED_SECRET_HANDLE_H_

#include "dds/export.h"
#include <stdint.h>
#include "dds/security/dds_security_api.h"


typedef struct DDS_Security_SharedSecretHandleImpl {

    DDS_Security_octet* shared_secret;
    DDS_Security_long shared_secret_size;
    DDS_Security_octet challenge1[DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE];
    DDS_Security_octet challenge2[DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE];

} DDS_Security_SharedSecretHandleImpl;

DDS_EXPORT const DDS_Security_octet* get_challenge1_from_secret_handle( DDS_Security_SharedSecretHandle handle);

DDS_EXPORT const DDS_Security_octet* get_challenge2_from_secret_handle( DDS_Security_SharedSecretHandle handle );

DDS_EXPORT const DDS_Security_octet* get_secret_from_secret_handle( DDS_Security_SharedSecretHandle handle );

DDS_EXPORT int32_t get_secret_size_from_secret_handle( DDS_Security_SharedSecretHandle handle );

#endif /* SRC_SECURITY_CORE_INCLUDE_SHARED_SECRET_H_ */

