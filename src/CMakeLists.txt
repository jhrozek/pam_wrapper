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

add_library(pam_matrix MODULE modules/pam_matrix.c)
set_property(TARGET pam_matrix PROPERTY PREFIX "")

set(PAM_LIBRARIES
    pam
    pam_misc)

target_link_libraries(pam_matrix
			${PAM_LIBRARIES})

set(PWRAP_PRIVATE_LIBRARIES
	${LIB_INSTALL_DIR}/pam_wrapper)

install(
  TARGETS
    pam_matrix
  LIBRARY DESTINATION ${PWRAP_PRIVATE_LIBRARIES}
  ARCHIVE DESTINATION ${PWRAP_PRIVATE_LIBRARIES}
)

# This needs to be at the end
if (POLICY CMP0026)
    cmake_policy(SET CMP0026 OLD)
endif()
get_target_property(PAM_WRAPPER_LOCATION pam_wrapper LOCATION)
set(PAM_WRAPPER_LOCATION ${PAM_WRAPPER_LOCATION} PARENT_SCOPE)
