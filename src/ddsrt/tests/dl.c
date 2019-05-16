/*
 * Copyright(c) 2019 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "CUnit/Test.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/library.h"
#include "dds/ddsrt/environ.h"
#include "dl_test.h"

#define TEST_LIB_FILE     ""TEST_LIB_PREFIX""TEST_LIB_NAME""TEST_LIB_SUFFIX""
#define TEST_LIB_ABSOLUTE ""TEST_LIB_DIR""TEST_LIB_SEP""TEST_LIB_FILE""

#define TEST_ABORT_IF_NULL(var, msg) \
do { \
  if (var == NULL) { \
    char buffer[256]; \
    r = ddsrt_dlerror(buffer, sizeof(buffer)); \
    CU_ASSERT_EQUAL_FATAL(r, DDS_RETCODE_OK); \
    printf("\n%s", buffer); \
    CU_FAIL_FATAL(msg); \
  } \
} while(0)


/*
 * Load a library.
 */
CU_Test(ddsrt_library, dlopen_path)
{
  dds_retcode_t r;
  ddsrt_lib l;

  printf("Absolute lib: %s\n", TEST_LIB_ABSOLUTE);
  l = ddsrt_dlopen(TEST_LIB_ABSOLUTE, false);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l, "ddsrt_dlopen() failed. Is the proper library path set?");

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}

CU_Test(ddsrt_library, dlopen_file)
{
  dds_retcode_t r;
  ddsrt_lib l;

  l = ddsrt_dlopen(TEST_LIB_FILE, false);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l, "ddsrt_dlopen() failed. Is the proper library path set?");

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}

CU_Test(ddsrt_library, dlopen_name)
{
  dds_retcode_t r;
  ddsrt_lib l;

  l = ddsrt_dlopen(TEST_LIB_NAME, true);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l, "ddsrt_dlopen() failed. Is the proper library path set?");

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}

CU_Test(ddsrt_library, dlopen_unknown)
{
  char buffer[256];
  dds_retcode_t r;
  ddsrt_lib l;

  l = ddsrt_dlopen("UnknownLib", false);
  CU_ASSERT_PTR_NULL_FATAL(l);

  r = ddsrt_dlerror(buffer, sizeof(buffer));
  CU_ASSERT_EQUAL_FATAL(r, DDS_RETCODE_OK);
  printf("\n%s", buffer);
}

CU_Test(ddsrt_library, dlsym)
{
  dds_retcode_t r;
  ddsrt_lib l;
  void* f;

  l = ddsrt_dlopen(TEST_LIB_NAME, true);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l, "ddsrt_dlopen() failed. Is the proper library path set?");

  f = ddsrt_dlsym(l, "get_int");
  CU_ASSERT_PTR_NOT_NULL(f);
  TEST_ABORT_IF_NULL(f, "ddsrt_dlsym(l, \"get_int\") failed.");

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}

CU_Test(ddsrt_library, dlsym_unknown)
{
  char buffer[256];
  dds_retcode_t r;
  ddsrt_lib l;
  void* f;

  l = ddsrt_dlopen(TEST_LIB_NAME, true);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l,"ddsrt_dlopen() failed. Is the proper library path set?");

  f = ddsrt_dlsym(l, "UnknownSym");
  CU_ASSERT_PTR_NULL_FATAL(f);

  r = ddsrt_dlerror(buffer, sizeof(buffer));
  CU_ASSERT_EQUAL_FATAL(r, DDS_RETCODE_OK);
  printf("\n%s", buffer);

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}

typedef void (*func_set_int)(int val);
typedef int  (*func_get_int)(void);
CU_Test(ddsrt_library, call)
{
  int get_int = 0;
  int set_int = 1234;
  func_get_int f_get;
  func_set_int f_set;
  dds_retcode_t r;
  ddsrt_lib l;

  l = ddsrt_dlopen(TEST_LIB_NAME, true);
  CU_ASSERT_PTR_NOT_NULL(l);
  TEST_ABORT_IF_NULL(l, "ddsrt_dlopen() failed. Is the proper library path set?");

  f_get = (func_get_int)ddsrt_dlsym(l, "get_int");
  CU_ASSERT_PTR_NOT_NULL(f_get);
  TEST_ABORT_IF_NULL(f_get, "ddsrt_dlsym(l, \"get_int\") failed.");

  f_set = (func_set_int)ddsrt_dlsym(l, "set_int");
  CU_ASSERT_PTR_NOT_NULL(f_set);
  TEST_ABORT_IF_NULL(f_set, "ddsrt_dlsym(l, \"set_int\") failed.");

  f_set(set_int);
  get_int = f_get();
  CU_ASSERT_EQUAL(set_int, get_int);

  r = ddsrt_dlclose(l);
  CU_ASSERT_EQUAL(r, DDS_RETCODE_OK);
}