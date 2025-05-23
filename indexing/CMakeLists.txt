set(IRODS_POLICY_NAME "indexing")
set(IRODS_PLUGIN_TARGET_NAME "${IRODS_TARGET_NAME_PREFIX}-${IRODS_POLICY_NAME}")

string(REPLACE "_" "-" IRODS_POLICY_NAME_HYPHENS "${IRODS_POLICY_NAME}")
set(IRODS_POLICY_PACKAGE_COMPONENT "${IRODS_POLICY_NAME_HYPHENS}")

include(ObjectTargetHelpers)

add_library(
	"${IRODS_PLUGIN_TARGET_NAME}"
	MODULE
	"${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/src/indexing_utilities.cpp"
)
target_link_objects(
	"${IRODS_PLUGIN_TARGET_NAME}"
	PRIVATE
	irods_cap_indexing_common_obj
)
target_link_libraries(
	"${IRODS_PLUGIN_TARGET_NAME}"
	PRIVATE
	irods_common
	irods_server
	nlohmann_json::nlohmann_json
	fmt::fmt
	"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
	"${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
)
target_include_directories(
	"${IRODS_PLUGIN_TARGET_NAME}"
	PRIVATE
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
	"${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
)
target_compile_definitions(
	"${IRODS_PLUGIN_TARGET_NAME}"
	PRIVATE
	BOOST_SYSTEM_NO_DEPRECATED
	RODS_SERVER
	ENABLE_RE
	${IRODS_COMPILE_DEFINITIONS}
	${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

install(
	TARGETS
	"${IRODS_PLUGIN_TARGET_NAME}"
	LIBRARY
	DESTINATION "${IRODS_PLUGINS_DIRECTORY}/rule_engines"
	COMPONENT "${IRODS_POLICY_PACKAGE_COMPONENT}"
)

install(
	FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/packaging/test_plugin_indexing.py"
	"${CMAKE_CURRENT_SOURCE_DIR}/packaging/atomic_metadata_ops.py"
	DESTINATION "${IRODS_HOME_DIRECTORY}/scripts/irods/test"
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT "${IRODS_POLICY_PACKAGE_COMPONENT}"
 )

install(
	FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/packaging/run_indexing_plugin_test.py"
	DESTINATION "${IRODS_HOME_DIRECTORY}/scripts"
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT "${IRODS_POLICY_PACKAGE_COMPONENT}"
)

string(TOUPPER "${IRODS_POLICY_PACKAGE_COMPONENT}" IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE)
string(REPLACE "_" "-" IRODS_PLUGIN_TARGET_NAME_HYPHENS "${IRODS_PLUGIN_TARGET_NAME}")

# CPack variables need to be set with PARENT_SCOPE, so they will be in scope for CPack.

set(CPACK_DEBIAN_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_PACKAGE_NAME "${IRODS_PLUGIN_TARGET_NAME_HYPHENS}" PARENT_SCOPE)
set(CPACK_DEBIAN_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_PACKAGE_DEPENDS "irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6" PARENT_SCOPE)
set(CPACK_DEBIAN_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/packaging/postinst;" PARENT_SCOPE)

set(CPACK_RPM_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_PACKAGE_NAME "${IRODS_PLUGIN_TARGET_NAME_HYPHENS}" PARENT_SCOPE)
set(CPACK_RPM_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_PACKAGE_REQUIRES "irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}" PARENT_SCOPE)
set(CPACK_RPM_${IRODS_POLICY_PACKAGE_COMPONENT_UPPERCASE}_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/postinst" PARENT_SCOPE)
