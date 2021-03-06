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
#ifndef DDSI_SERTOPIC_H
#define DDSI_SERTOPIC_H

#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/avl.h"
#include "dds/ddsc/dds_public_alloc.h"

#if defined (__cplusplus)
extern "C" {
#endif

struct ddsi_serdata;
struct ddsi_serdata_ops;

struct dds_topic;
typedef void (*topic_cb_t) (struct dds_topic * topic);

struct ddsi_sertopic_ops;

struct ddsi_sertopic {
  ddsrt_avl_node_t avlnode; /* index on name_typename */
  const struct ddsi_sertopic_ops *ops;
  const struct ddsi_serdata_ops *serdata_ops;
  uint32_t serdata_basehash;
  char *name_type_name;
  char *name;
  char *type_name;
  uint64_t iid;
  ddsrt_atomic_uint32_t refc; /* counts refs from entities, not from data */

  topic_cb_t status_cb;
  struct dds_topic * status_cb_entity;
};

/* Called when the refcount dropped to zero */
typedef void (*ddsi_sertopic_free_t) (struct ddsi_sertopic *tp);

/* Zero out a sample, used for generating samples from just a key value and in cleaning up
   after dds_return_loan */
typedef void (*ddsi_sertopic_zero_samples_t) (const struct ddsi_sertopic *d, void *samples, size_t count);

/* (Re)allocate an array of samples, used in growing loaned sample arrays in dds_read */
typedef void (*ddsi_sertopic_realloc_samples_t) (void **ptrs, const struct ddsi_sertopic *d, void *old, size_t oldcount, size_t count);

/* Release any memory allocated by ddsi_sertopic_to_sample (also undo sertopic_alloc_sample if "op" so requests) */
typedef void (*ddsi_sertopic_free_samples_t) (const struct ddsi_sertopic *d, void **ptrs, size_t count, dds_free_op_t op);

struct ddsi_sertopic_ops {
  ddsi_sertopic_free_t free;
  ddsi_sertopic_zero_samples_t zero_samples;
  ddsi_sertopic_realloc_samples_t realloc_samples;
  ddsi_sertopic_free_samples_t free_samples;
};

DDS_EXPORT struct ddsi_sertopic *ddsi_sertopic_ref (const struct ddsi_sertopic *tp);
DDS_EXPORT void ddsi_sertopic_unref (struct ddsi_sertopic *tp);
DDS_EXPORT uint32_t ddsi_sertopic_compute_serdata_basehash (const struct ddsi_serdata_ops *ops);

DDS_EXPORT inline void ddsi_sertopic_free (struct ddsi_sertopic *tp) {
  tp->ops->free (tp);
}
DDS_EXPORT inline void ddsi_sertopic_zero_samples (const struct ddsi_sertopic *tp, void *samples, size_t count) {
  tp->ops->zero_samples (tp, samples, count);
}
DDS_EXPORT inline void ddsi_sertopic_realloc_samples (void **ptrs, const struct ddsi_sertopic *tp, void *old, size_t oldcount, size_t count)
{
  tp->ops->realloc_samples (ptrs, tp, old, oldcount, count);
}
DDS_EXPORT inline void ddsi_sertopic_free_samples (const struct ddsi_sertopic *tp, void **ptrs, size_t count, dds_free_op_t op) {
  tp->ops->free_samples (tp, ptrs, count, op);
}
DDS_EXPORT inline void ddsi_sertopic_zero_sample (const struct ddsi_sertopic *tp, void *sample) {
  ddsi_sertopic_zero_samples (tp, sample, 1);
}
DDS_EXPORT inline void *ddsi_sertopic_alloc_sample (const struct ddsi_sertopic *tp) {
  void *ptr;
  ddsi_sertopic_realloc_samples (&ptr, tp, NULL, 0, 1);
  return ptr;
}
DDS_EXPORT inline void ddsi_sertopic_free_sample (const struct ddsi_sertopic *tp, void *sample, dds_free_op_t op) {
  ddsi_sertopic_free_samples (tp, &sample, 1, op);
}

#if defined (__cplusplus)
}
#endif

#endif
