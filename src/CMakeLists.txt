project(libpam_wrapper C)

include_directories(${CMAKE_BINARY_DIR})
add_library(pam_wrapper SHARED pam_wrapper.c)
target_link_libraries(pam_wrapper ${PAMWRAP_REQUIRED_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

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
target_link_libraries(pamtest
			${PAM_LIBRARIES})

install(
  TARGETS
    pamtest
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

set(PAM_MODULES pam_matrix pam_get_items pam_set_items)

set(PWRAP_PRIVATE_LIBRARIES
	${LIB_INSTALL_DIR}/pam_wrapper)

foreach(_PAM_MODULE ${PAM_MODULES})
	add_library(${_PAM_MODULE} MODULE modules/${_PAM_MODULE}.c)
	set_property(TARGET ${_PAM_MODULE} PROPERTY PREFIX "")

	target_link_libraries(${_PAM_MODULE}
				${PAM_LIBRARIES})

	install(
		TARGETS
			${_PAM_MODULE}
		LIBRARY DESTINATION ${PWRAP_PRIVATE_LIBRARIES}
		ARCHIVE DESTINATION ${PWRAP_PRIVATE_LIBRARIES})
endforeach()

# This needs to be at the end
if (POLICY CMP0026)
    cmake_policy(SET CMP0026 OLD)
endif()
get_target_property(PAM_WRAPPER_LOCATION pam_wrapper LOCATION)
set(PAM_WRAPPER_LOCATION ${PAM_WRAPPER_LOCATION} PARENT_SCOPE)
