/*
 * Copyright(c) 2006 to 2018 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#ifndef DDSRT_LIBRARY_H
#define DDSRT_LIBRARY_H

#include "dds/export.h"
#include "dds/ddsrt/types.h"
#include "dds/ddsrt/retcode.h"

#if defined (__cplusplus)
extern "C" {
#endif

typedef void *ddsrt_lib;

/**
 * @brief Load a dynamic shared library.
 *
 * The function ddsrt_dlopen() loads the dynamic shared object (shared library)
 * file, identified by 'name', and returns a handle for the loaded library.
 *
 * If the 'translate' boolean is true, this function will first try to open the
 * library with a translated 'name'. Translated in this context means that if
 * "mylibrary" is provided, it will be translated into libmylibrary.so,
 * libmylibrary.dylib or mylibrary.dll depending on the platform.
 * This translation only happens when the given name does not contain
 * a directory.
 * If the function isn't able to load the library with the translated name, it
 * will still try the given name.
 *
 * @param[in]   name        Library file name.
 * @param[in]   translate   Automatic name translation on/off.
 *
 * @returns A ddsrt_lib library handle.
 *
 * @retval !NULL
 *             Library was loaded.
 * @retval NULL
 *             Loading failed.
 *             Use ddsrt_dlerror() to diagnose the failure.
 */
DDS_EXPORT ddsrt_lib
ddsrt_dlopen(
    const char *name,
    bool translate);

/**
 * @brief Close the library.
 *
 * The function ddsrt_dlclose() informs the system that the
 * library, identified by 'handle', is no longer needed.
 * will get the memory address of a symbol,
 * identified by 'symbol', from a loaded library 'handle'.
 *
 * @param[in]   handle      Library handle.
 *
 * @returns A dds_retcode_t indicating success or failure.
 *
 * @retval DDS_RETCODE_OK
 *             Library handle was successfully closed.
 * @retval DDS_RETCODE_ERROR
 *             Library closing failed.
 *             Use ddsrt_dlerror() to diagnose the failure.
 */
DDS_EXPORT dds_retcode_t
ddsrt_dlclose(
    ddsrt_lib handle);

/**
 * @brief Get the memory address of a symbol.
 *
 * The function ddsrt_dlsym() will get the memory address of a symbol,
 * identified by 'symbol', from a loaded library 'handle'.
 *
 * @param[in]   handle      Library handle.
 * @param[in]   symbol      Symbol name.
 *
 * @returns The memory address of the loaded symbol (void*).
 *
 * @retval !NULL
 *             Symbol was found in the loaded library.
 * @retval NULL
 *             Symbol was not found.
 *             Use ddsrt_dlerror() to diagnose the failure.
 */
DDS_EXPORT void*
ddsrt_dlsym(
    ddsrt_lib handle,
    const char *symbol);

/**
 * @brief Get the most recent library related error.
 *
 * The function ddsrt_dlerror() will return the most recent library
 * related error in human readable form.
 *
 * If no error was found, it's either due to the fact that there
 * actually was no error since init or last ddsrt_dlerror() call,
 * or due to an unknown unrelated error.
 *
 * @returns A dds_retcode_t indicating success or failure.
 *
 * @retval DDS_RETCODE_OK
 *             Most recent library related error returned.
 * @retval DDS_RETCODE_NOT_FOUND
 *             No library related error found.
 */
DDS_EXPORT dds_retcode_t
ddsrt_dlerror(
    char *buf,
    size_t buflen);

#if defined (__cplusplus)
}
#endif

#endif /* DDSRT_LIBRARY_H */