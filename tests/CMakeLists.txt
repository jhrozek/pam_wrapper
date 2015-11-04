project(tests C)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMOCKA_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
)

set(PAM_MATRIX_PATH "${CMAKE_BINARY_DIR}/src/modules/pam_matrix.so")

configure_file(services/matrix.in ${CMAKE_CURRENT_BINARY_DIR}/services/matrix @ONLY)

# Some tests use a passdb as argument for pam_matrix
set(PASSDB_RO_PATH ${CMAKE_CURRENT_BINARY_DIR}/passdb_ro)
configure_file(passdb_ro ${PASSDB_RO_PATH} @ONLY)
configure_file(services/matrix_opt.in ${CMAKE_CURRENT_BINARY_DIR}/services/matrix_opt @ONLY)

set(PASSDB_PY_PATH ${CMAKE_CURRENT_BINARY_DIR}/passdb_py)
configure_file(passdb_py ${PASSDB_PY_PATH} @ONLY)
configure_file(services/matrix_py.in ${CMAKE_CURRENT_BINARY_DIR}/services/matrix_py @ONLY)

configure_file(services/pwrap_get_set.in ${CMAKE_CURRENT_BINARY_DIR}/services/pwrap_get_set @ONLY)

if (OSX)
	set(TEST_ENVIRONMENT DYLD_FORCE_FLAT_NAMESPACE=1;DYLD_INSERT_LIBRARIES=${PAM_WRAPPER_LOCATION};PAM_WRAPPER=1;PAM_WRAPPER_SERVICE_DIR=${CMAKE_CURRENT_BINARY_DIR}/services})
	add_definitions(-DOSX)
else ()
	set(TEST_ENVIRONMENT LD_PRELOAD=${PAM_WRAPPER_LOCATION};PAM_WRAPPER=1;PAM_WRAPPER_SERVICE_DIR=${CMAKE_CURRENT_BINARY_DIR}/services)
endif ()

set(PAM_LIBRARIES pam)
if (HAVE_PAM_MISC)
	list(APPEND PAM_LIBRARIES pam_misc)
endif (HAVE_PAM_MISC)

set(TEST_LIBRARIES
    pamtest
    ${CMOCKA_LIBRARY}
    ${PAM_LIBRARIES}
)

add_cmocka_test(test_pam_wrapper test_pam_wrapper.c ${TEST_LIBRARIES})
set_property(
    TEST
        test_pam_wrapper
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})

add_test(pypamtest_test ${CMAKE_CURRENT_SOURCE_DIR}/pypamtest_test.py)
set_property(
    TEST
        pypamtest_test
    PROPERTY
        ENVIRONMENT ${TEST_ENVIRONMENT})
