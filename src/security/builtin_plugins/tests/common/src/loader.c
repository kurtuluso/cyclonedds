#include <CUnit/Test.h>
#include "loader.h"
#include "dds/ddsrt/dynlib.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"
#include "sys/stat.h"
#include "assert.h"
#include "stdio.h"
#include "string.h"
#include "dds/security/core/dds_security_utils.h"

struct plugin_info {
    void *context;
    ddsrt_dynlib_t lib_handle;
    plugin_init func_init;
    plugin_finalize func_fini;
};

struct plugins_hdl {
    struct plugin_info plugin_ac;
    struct plugin_info plugin_auth;
    struct plugin_info plugin_crypto;
};

static void*
load_plugin(
        struct plugin_info *info,
        const char *name_lib,
        const char *name_init,
        const char *name_fini)
{
    dds_retcode_t result;
    void *plugin = NULL;
    assert(info);

    result = ddsrt_dlopen(name_lib, true, &info->lib_handle);
    if (result == DDS_RETCODE_OK && info->lib_handle) {

        result = ddsrt_dlsym(info->lib_handle, name_init, (void **)&info->func_init);
        if( result != DDS_RETCODE_OK || info->func_init == NULL) {
        	 printf("ERROR: could not init %s\n. Invalid init function: %s", name_lib, name_init);
        	 return plugin;
        }

        result = ddsrt_dlsym(info->lib_handle, name_fini, (void **)&info->func_fini);
        if( result != DDS_RETCODE_OK || info->func_fini == NULL ) {
					 printf("ERROR: could not init %s\n. Invalid fini function: %s", name_lib, name_fini);
					 return plugin;
				}

				char * init_parameters = "";
				(void)info->func_init(init_parameters, &plugin);
				if (plugin) {
						info->context = plugin;
				} else {
						printf("ERROR: could not init %s\n", name_lib);
				}
    } else {
    	char buffer[300];
    	ddsrt_dlerror(buffer,300);
        printf("ERROR: could not load %s. %s\n", name_lib, buffer);
    }
    return plugin;
}

struct plugins_hdl*
load_plugins(
        dds_security_access_control **ac,
        dds_security_authentication **auth,
        dds_security_cryptography   **crypto)
{
    struct plugins_hdl *plugins = ddsrt_malloc(sizeof(struct plugins_hdl));
    assert(plugins);
    memset(plugins, 0, sizeof(struct plugins_hdl));
    if (ac) {
        *ac = load_plugin(&(plugins->plugin_ac),
                          "dds_security_ac",
                          "init_access_control",
                          "finalize_access_control");
        if (!(*ac)) {
            goto err;
        }
    }
    if (auth) {
        *auth = load_plugin(&(plugins->plugin_auth),
                            //"dds_security_auth",
                            "dds_security_auth",
                            "init_authentication",
                            "finalize_authentication");
        if (!(*auth)) {
            goto err;
        }
    }
    if (crypto) {
        *crypto = load_plugin(&(plugins->plugin_crypto),
                              "dds_security_crypto",
                              "init_crypto",
                              "finalize_crypto");
        if (!(*crypto)) {
            goto err;
        }
    }
    return plugins;

err:
    unload_plugins(plugins);
    return NULL;
}

static void
unload_plugin(
        struct plugin_info *info)
{
    dds_retcode_t result;
    assert(info);

    if (info->lib_handle) {
        if (info->func_fini && info->context) {
            info->func_fini(info->context);
        }
        result = ddsrt_dlclose( info->lib_handle );
        if ( result != 0 ){
        	printf( "Error occured while closing the library\n");
        }
    }
}

void
unload_plugins(
        struct plugins_hdl *plugins)
{
    assert (plugins);
    unload_plugin(&(plugins->plugin_ac));
    unload_plugin(&(plugins->plugin_auth));
    unload_plugin(&(plugins->plugin_crypto));
    ddsrt_free(plugins);
}

static size_t
regular_file_size(
         const char *filename)
{
    size_t sz = 0;
    /* Provided? */
    if (filename) {
        /* Accessible? */
#if _WIN32
    		struct _stat stat_info;
    		int ret = _stat( filename, &stat_info );
#else
    		struct stat stat_info;
    		int ret = stat( filename, &stat_info );
#endif
        if ( ret == 0 ) {
            /* Regular? */
#ifdef WIN32
			if (stat_info.st_mode & _S_IFREG) {				
#else
			if (S_ISREG(stat_info.st_mode)) {
#endif
                /* Yes, so get the size. */
                sz = ( size_t ) stat_info.st_size;
            }
        }
    }
    return sz;
}

char *
load_file_contents(
    const char *filename)
{
    char *document = NULL;
    char *fname;
    size_t sz, r;
    FILE *fp;

    assert(filename);

    /* Get portable file name. */
    fname = DDS_Security_normalize_file( filename );
    if (fname) {
        /* Get size if it is a accessible regular file (no dir or link). */
        sz = regular_file_size(fname);
        if (sz > 0) {
            /* Open the actual file. */
            fp = fopen(fname, "r");
            if (fp) {
                /* Read the content. */
                document = ddsrt_malloc(sz + 1);
                r = fread(document, 1, sz, fp);
                if (r == 0) {
                    ddsrt_free(document);
                    document = NULL;
                } else {
                    document[r] = '\0';
                }
                (void)fclose(fp);
            }
        }
        ddsrt_free(fname);
    }

    return document;
}
