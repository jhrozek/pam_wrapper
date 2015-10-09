project(pam_wrapper-headers C)

set(libpamtest_HDRS
  libpamtest.h
)

install(
  FILES
    ${libpamtest_HDRS}
  DESTINATION
    ${INCLUDE_INSTALL_DIR}
  COMPONENT
    headers
)
