project(libpam_wrapper C)

include_directories(${CMAKE_BINARY_DIR})

###########################################################
### pam_wrapper
###########################################################

add_library(pam_wrapper SHARED pam_wrapper.c)

set(PAM_WRAPPER_LIBRARIES
	${PAMWRAP_REQUIRED_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT})
if (HAVE_OPENPAM)
	list(APPEND PAM_WRAPPER_LIBRARIES pam)
endif (HAVE_OPENPAM)

target_link_libraries(pam_wrapper ${PAM_WRAPPER_LIBRARIES})

set_target_properties(
  pam_wrapper
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
)

install(
  TARGETS
    pam_wrapper
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

###########################################################
### libpamtest
###########################################################

set(pamtest_SOURCES
    libpamtest.c
)

set(pamtest_HEADERS
    ${CMAKE_SOURCE_DIR}/include/libpamtest.h
)
include_directories(${CMAKE_SOURCE_DIR}/include)

set(PAM_LIBRARIES pam)
if (HAVE_PAM_MISC)
	list(APPEND PAM_LIBRARIES pam_misc)
endif (HAVE_PAM_MISC)

add_library(pamtest SHARED
            ${pamtest_SOURCES}
            ${pamtest_HEADERS}
)
target_link_libraries(pamtest ${PAM_LIBRARIES})

set_target_properties(pamtest
    PROPERTIES
        VERSION ${LIBRARY_VERSION}
        SOVERSION ${LIBRARY_SOVERSION})

install(TARGETS pamtest
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR})

add_subdirectory(modules)
if (PYTHONLIBS_FOUND)
    add_subdirectory(python)
endif()

# This needs to be at the end
if (POLICY CMP0026)
    cmake_policy(SET CMP0026 OLD)
endif()
get_target_property(PAM_WRAPPER_LOCATION pam_wrapper LOCATION)
set(PAM_WRAPPER_LOCATION ${PAM_WRAPPER_LOCATION} PARENT_SCOPE)
