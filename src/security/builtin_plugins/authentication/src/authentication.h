/*
 * authentication.h
 *
 *  Created on: Jan 15, 2018
 *      Author: kurtulus oksuztepe
 */

#ifndef SECURITY_BUILTIN_PLUGINS_AUTHENTICATION_H_
#define SECURITY_BUILTIN_PLUGINS_AUTHENTICATION_H_

#include <dds/ddsrt/atomics.h>

DDS_EXPORT int
init_authentication(const char *argument, void **context);

DDS_EXPORT int
finalize_authentication(void *context);

#endif /* SECURITY_BUILTIN_PLUGINS_AUTHENTICATION_H_ */
