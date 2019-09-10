/*
 * shared_secret_handle.h
 *
 *  Created on: May 9, 2018
 *      Author: kurtulus
 */

#include "dds/security/core/shared_secret.h"

const DDS_Security_octet*
get_challenge1_from_secret_handle(DDS_Security_SharedSecretHandle handle)
{

    DDS_Security_SharedSecretHandleImpl *secret = (DDS_Security_SharedSecretHandleImpl *)(uintptr_t)handle;
    return secret->challenge1;
}

const DDS_Security_octet*
get_challenge2_from_secret_handle(DDS_Security_SharedSecretHandle handle)
{
    DDS_Security_SharedSecretHandleImpl *secret = (DDS_Security_SharedSecretHandleImpl *)(uintptr_t)handle;
    return secret->challenge2;
}

const DDS_Security_octet*
get_secret_from_secret_handle(DDS_Security_SharedSecretHandle handle)
{
    DDS_Security_SharedSecretHandleImpl *secret = (DDS_Security_SharedSecretHandleImpl *)(uintptr_t)handle;
    return secret->shared_secret;
}


int32_t
get_secret_size_from_secret_handle( DDS_Security_SharedSecretHandle handle ){
    DDS_Security_SharedSecretHandleImpl *secret = (DDS_Security_SharedSecretHandleImpl *)(uintptr_t)handle;
    return secret->shared_secret_size;

}
