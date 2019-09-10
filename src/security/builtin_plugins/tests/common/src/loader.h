#ifndef _DBT_SECURITY_PLUGINS_LOADER_H_
#define _DBT_SECURITY_PLUGINS_LOADER_H_

#include "dds/security/dds_security_api.h"

struct plugins_hdl;

struct plugins_hdl*
load_plugins(
        dds_security_access_control **ac,
        dds_security_authentication **auth,
        dds_security_cryptography   **crypto);

void
unload_plugins(
        struct plugins_hdl *plugins);

char*
load_file_contents(
        const char *filename);

#endif
