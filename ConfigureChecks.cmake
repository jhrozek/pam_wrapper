include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckStructHasMember)
include(CheckPrototypeDefinition)
include(TestBigEndian)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

# HEADERS
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(security/pam_appl.h HAVE_SECURITY_PAM_APPL_H)

# FUNCTIONS
check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(snprintf HAVE_SNPRINTF)

# OPTIONS

if (LINUX)
    if (HAVE_SYS_SYSCALL_H)
       list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DHAVE_SYS_SYSCALL_H")
    endif (HAVE_SYS_SYSCALL_H)
    if (HAVE_SYSCALL_H)
        list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DHAVE_SYSCALL_H")
    endif (HAVE_SYSCALL_H)

    set(CMAKE_REQUIRED_DEFINITIONS)
endif (LINUX)

check_c_source_compiles("
#include <stdbool.h>
int main(void) {
    bool x;
    bool *p_x = &x;
    __atomic_load(p_x, &x, __ATOMIC_RELAXED);
    return 0;
}" HAVE_GCC_ATOMIC_BUILTINS)

check_c_source_compiles("
__thread int tls;

int main(void) {
    return 0;
}" HAVE_GCC_THREAD_LOCAL_STORAGE)

check_c_source_compiles("
void test_constructor_attribute(void) __attribute__ ((constructor));

void test_constructor_attribute(void)
{
     return;
}

int main(void) {
     return 0;
}" HAVE_CONSTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
void test_destructor_attribute(void) __attribute__ ((destructor));

void test_destructor_attribute(void)
{
    return;
}

int main(void) {
    return 0;
}" HAVE_DESTRUCTOR_ATTRIBUTE)

check_c_source_compiles("
void log_fn(const char *format, ...) __attribute__ ((format (printf, 1, 2)));

int main(void) {
    return 0;
}" HAVE_FUNCTION_ATTRIBUTE_FORMAT)

# SYSTEM LIBRARIES

check_library_exists(dl dlopen "" HAVE_LIBDL)
if (HAVE_LIBDL)
    find_library(DLFCN_LIBRARY dl)
    set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${DLFCN_LIBRARY})
endif (HAVE_LIBDL)

if (OSX)
    set(HAVE_APPLE 1)
endif (OSX)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)

set(UIDWRAP_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} CACHE INTERNAL "uidwrap required system libraries")
