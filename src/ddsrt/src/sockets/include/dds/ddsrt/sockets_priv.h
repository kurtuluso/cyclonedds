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
#ifndef DDSRT_SOCKETS_PRIV_H
#define DDSRT_SOCKETS_PRIV_H

#include <assert.h>

#include "dds/ddsrt/misc.h"
#include "dds/ddsrt/sockets.h"
#include "dds/ddsrt/time.h"

#if defined(__cplusplus)
extern "C" {
#endif

#if _WIN32
typedef long ddsrt_tv_sec_t;
typedef long ddsrt_tv_usec_t;
#else
typedef time_t ddsrt_tv_sec_t;
typedef suseconds_t ddsrt_tv_usec_t;
#endif

#define DDSRT_TIME_T_MAX \
  (DDSRT_MAX_INTEGER(ddsrt_tv_sec_t))

/**
 * @brief Convert a relative time to a timeval rounding up.
 *
 * @param[in]   reltime  Relative time to convert.
 * @param[out]  tv       struct timeval* where timeout is stored.
 *
 * @returns NULL if @reltime was @DDS_INFINITY, the value of @tv otherwise.
 */
inline struct timeval *
ddsrt_duration_to_timeval_ceil(dds_duration_t reltime, struct timeval *tv)
{
  assert(tv != NULL);

  if (reltime == DDS_INFINITY) {
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return NULL;
  } else if (reltime > 0) {
    dds_duration_t max_nsecs;
    if (DDSRT_TIME_T_MAX == INT32_MAX) {
      max_nsecs = INT32_MAX * DDS_NSECS_IN_SEC;
    } else {
      assert(DDSRT_TIME_T_MAX == INT64_MAX);
      max_nsecs = DDSRT_TIME_T_MAX / DDS_NSECS_IN_SEC;
    }

    if (reltime < (max_nsecs - DDS_NSECS_IN_USEC - 1)) {
      reltime += (DDS_NSECS_IN_USEC - 1);
      tv->tv_sec = (ddsrt_tv_sec_t)(reltime / DDS_NSECS_IN_SEC);
      tv->tv_usec = (ddsrt_tv_usec_t)((reltime % DDS_NSECS_IN_SEC) / DDS_NSECS_IN_USEC);
    } else {
      tv->tv_sec = DDSRT_TIME_T_MAX;
      tv->tv_usec = 999999;
    }
  } else {
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }

  return tv;
}

#if defined(__cplusplus)
}
#endif

#endif /* DDSRT_SOCKETS_PRIV_H */
