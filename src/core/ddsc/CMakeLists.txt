#
# Copyright(c) 2006 to 2018 ADLINK Technology Limited and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
PREPEND(srcs_ddsc "${CMAKE_CURRENT_LIST_DIR}/src"
    dds_alloc.c
    dds_builtin.c
    dds_coherent.c
    dds_participant.c
    dds_reader.c
    dds_writer.c
    dds_init.c
    dds_publisher.c
    dds_rhc.c
    dds_domain.c
    dds_instance.c
    dds_qos.c
    dds_handles.c
    dds_entity.c
    dds_querycond.c
    dds_topic.c
    dds_listener.c
    dds_read.c
    dds_stream.c
    dds_waitset.c
    dds_readcond.c
    dds_guardcond.c
    dds_subscriber.c
    dds_write.c
    dds_whc.c
    dds_whc_builtintopic.c
    dds_serdata_builtintopic.c
    dds_sertopic_builtintopic.c
)

PREPEND(hdrs_public_ddsc "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include/dds>$<INSTALL_INTERFACE:include/dds>"
    dds.h
    ddsc/dds_public_error.h
    ddsc/dds_public_impl.h
    ddsc/dds_public_listener.h
    ddsc/dds_public_qos.h
    ddsc/dds_public_status.h
)

PREPEND(hdrs_private_ddsc "${CMAKE_CURRENT_LIST_DIR}/src"
    dds__alloc.h
    dds__builtin.h
    dds__domain.h
    dds__handles.h
    dds__entity.h
    dds__init.h
    dds__listener.h
    dds__participant.h
    dds__publisher.h
    dds__qos.h
    dds__querycond.h
    dds__readcond.h
    dds__guardcond.h
    dds__reader.h
    dds__rhc.h
    dds__stream.h
    dds__subscriber.h
    dds__topic.h
    dds__types.h
    dds__write.h
    dds__writer.h
    dds__whc.h
    dds__whc_builtintopic.h
    dds__serdata_builtintopic.h
)

generate_export_header(
    ddsc
    BASE_NAME DDS
    EXPORT_FILE_NAME "${CMAKE_CURRENT_BINARY_DIR}/include/dds/export.h"
)

target_include_directories(
  ddsc PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>")

target_sources(ddsc
    PRIVATE
        ${srcs_ddsc}
        ${hdrs_private_ddsc}
    PUBLIC
        ${hdrs_public_ddsc}
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>$<INSTALL_INTERFACE:include>/dds/export.h"
)

target_include_directories(ddsc
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
    PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src")

target_include_directories(ddsc INTERFACE $<INSTALL_INTERFACE:include>)

install(
  DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/dds"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT dev)

install(
  DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/ddsc"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT dev)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/include/dds/export.h"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/dds"
  COMPONENT dev)

# TODO: improve test inclusion.
if((BUILD_TESTING) AND ((NOT DEFINED MSVC_VERSION) OR (MSVC_VERSION GREATER "1800")))
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tests")
endif()

