project(pypamtest)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${pam_wrapper-headers_DIR})
include_directories(${PYTHON_INCLUDE_DIR})

add_library(pypamtest MODULE pypamtest.c)
target_link_libraries(pypamtest pamtest pam ${PYTHON_LIBRARY})

set_target_properties(
  pypamtest
    PROPERTIES
	PREFIX "")

