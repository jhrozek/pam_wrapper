project(pypamtest C)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${pam_wrapper-headers_DIR})
include_directories(${PYTHON_INCLUDE_DIR})

python_add_module(pypamtest pypamtest.c)
target_link_libraries(pypamtest pamtest ${PYTHON_LIBRARY})

install(
    TARGETS
        pypamtest
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/${PYTHON_SITELIB}
)
