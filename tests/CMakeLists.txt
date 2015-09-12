project(tests C)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMOCKA_INCLUDE_DIR}
)

configure_file(services/pwrap_pam.in ${CMAKE_CURRENT_BINARY_DIR}/services/pwrap_pam @ONLY)

set(PASSDB_PATH
	${CMAKE_CURRENT_BINARY_DIR}/passdb)
configure_file(passdb ${PASSDB_PATH} @ONLY)


if (OSX)
	set(TEST_ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${PAM_WRAPPER_LOCATION};PAM_WRAPPER=1;PAM_WRAPPER_CONFDIR=${CMAKE_CURRENT_BINARY_DIR})
	add_definitions(-DOSX)
else ()
	set(TEST_ENVIRONMENT LD_PRELOAD=${PAM_WRAPPER_LOCATION};PAM_WRAPPER=1;PAM_WRAPPER_CONFDIR=${CMAKE_CURRENT_BINARY_DIR};PWRAP_PASSDB=${PASSDB_PATH})
endif ()

add_library(pam_example MODULE pam_example.c)
set_property(TARGET pam_example PROPERTY PREFIX "")

set(PAM_LIBRARIES
	pam
	pam_misc)

target_link_libraries(pam_example
	${PAM_LIBRARIES})


add_cmocka_test(test_pam_wrapper test_pam_wrapper.c ${CMOCKA_LIBRARY} ${PAM_LIBRARIES})
set_property(
    TEST
        test_pam_wrapper
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})
