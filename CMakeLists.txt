project(pam_wrapper C)

# Required cmake version
cmake_minimum_required(VERSION 2.8.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "1")
set(APPLICATION_VERSION_MINOR "0")
set(APPLICATION_VERSION_PATCH "1")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# SOVERSION scheme: CURRENT.AGE.REVISION
#   If there was an incompatible interface change:
#     Increment CURRENT. Set AGE and REVISION to 0
#   If there was a compatible interface change:
#     Increment AGE. Set REVISION to 0
#   If the source code was changed, but there were no interface changes:
#     Increment REVISION.
set(LIBRARY_VERSION "0.0.2")
set(LIBRARY_SOVERSION "0")

set(PAMTEST_LIBRARY_VERSION "0.0.1")
set(PAMTEST_LIBRARY_SOVERSION "0")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions.cmake)
include(CPackConfig.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

find_package(PythonInterp)
set(Python_ADDITIONAL_VERSIONS 2.6 2.7 3.3 3.4)
find_package(PythonLibs)
find_package(PythonSiteLibs)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(src)
add_subdirectory(include)

if (UNIT_TESTING)
    find_package(CMocka REQUIRED)
    include(AddCMockaTest)
    add_subdirectory(tests)
endif (UNIT_TESTING)

# pkg-config file
get_filename_component(PAM_WRAPPER_LIB ${PAM_WRAPPER_LOCATION} NAME)

configure_file(pam_wrapper.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper.pc @ONLY)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

configure_file(libpamtest.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libpamtest.pc @ONLY)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libpamtest.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

# cmake config files
configure_file(pam_wrapper-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper-config-version.cmake @ONLY)
configure_file(pam_wrapper-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper-config.cmake @ONLY)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper-config-version.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/pam_wrapper-config.cmake
    DESTINATION
        ${CMAKE_INSTALL_DIR}/pam_wrapper
    COMPONENT
        devel
)

set(LIBPAMTEST_LIBRARY_NAME ${CMAKE_SHARED_LIBRARY_PREFIX}pamtest${CMAKE_SHARED_LIBRARY_SUFFIX})

configure_file(libpamtest-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/libpamtest-config.cmake @ONLY)
configure_file(libpamtest-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/libpamtest-config-version.cmake @ONLY)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/libpamtest-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/libpamtest-config-version.cmake
    DESTINATION
        ${CMAKE_INSTALL_DIR}/libpamtest
    COMPONENT
        devel
)

add_subdirectory(doc)
