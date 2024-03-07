set(POLICY_NAME "elasticsearch")

string(REPLACE "_" "-" POLICY_NAME_HYPHENS ${POLICY_NAME})
set(IRODS_PACKAGE_COMPONENT_POLICY_NAME "${POLICY_NAME_HYPHENS}")
string(TOUPPER ${IRODS_PACKAGE_COMPONENT_POLICY_NAME} IRODS_PACKAGE_COMPONENT_POLICY_NAME_UPPERCASE)

set(TARGET_NAME "${IRODS_TARGET_NAME_PREFIX}-${POLICY_NAME}")
string(REPLACE "_" "-" TARGET_NAME_HYPHENS ${TARGET_NAME})

include(IrodsExternals)

string(REPLACE ";" ", " ${TARGET_NAME}_PACKAGE_DEPENDENCIES_STRING "${IRODS_PACKAGE_DEPENDENCIES_LIST}")
unset(IRODS_PACKAGE_DEPENDENCIES_LIST)

set(
  IRODS_PLUGIN_POLICY_COMPILE_DEFINITIONS
  RODS_SERVER
  ENABLE_RE
)

set(
  IRODS_PLUGIN_POLICY_LINK_LIBRARIES
  irods_server
)

add_library(
  ${TARGET_NAME}
  MODULE
  ${CMAKE_CURRENT_SOURCE_DIR}/lib${TARGET_NAME}.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/utilities.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/configuration.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/plugin_specific_configuration.cpp
)

target_include_directories(
  ${TARGET_NAME}
  PRIVATE
  ${IRODS_INCLUDE_DIRS}
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
  ${IRODS_EXTERNALS_FULLPATH_FMT}/include
)

target_link_libraries(
  ${TARGET_NAME}
  PRIVATE
  ${IRODS_PLUGIN_POLICY_LINK_LIBRARIES}
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_url.so
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so
  irods_common
  nlohmann_json::nlohmann_json
)

target_compile_definitions(
  ${TARGET_NAME}
  PRIVATE
  ${IRODS_PLUGIN_POLICY_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  BOOST_SYSTEM_NO_DEPRECATED
  IRODS_PLUGIN_VERSION="${IRODS_PLUGIN_VERSION}"
)
target_compile_options(${TARGET_NAME} PRIVATE -Wno-write-strings)
set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD ${IRODS_CXX_STANDARD})

install(
  TARGETS
  ${TARGET_NAME}
  LIBRARY
  DESTINATION ${IRODS_PLUGINS_DIRECTORY}/rule_engines
  COMPONENT ${IRODS_PACKAGE_COMPONENT_POLICY_NAME}
)

set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_DEBIAN_${IRODS_PACKAGE_COMPONENT_POLICY_NAME_UPPERCASE}_PACKAGE_NAME ${TARGET_NAME_HYPHENS})

set(CPACK_DEBIAN_${IRODS_PACKAGE_COMPONENT_POLICY_NAME_UPPERCASE}_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, ${${TARGET_NAME}_PACKAGE_DEPENDENCIES_STRING}, irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6")

set(CPACK_RPM_${IRODS_PACKAGE_COMPONENT_POLICY_NAME_UPPERCASE}_PACKAGE_NAME ${TARGET_NAME_HYPHENS})

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/packaging/${POLICY_NAME}/postinst;")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/${POLICY_NAME}/postinst")

if (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos linux" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "almalinux" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "rocky")
  set(CPACK_RPM_${IRODS_PACKAGE_COMPONENT_POLICY_NAME}_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, ${${TARGET_NAME}_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}, openssl")
elseif (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "opensuse")
  set(CPACK_RPM_${IRODS_PACKAGE_COMPONENT_POLICY_NAME}_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}, libopenssl1_0_0")
endif()
