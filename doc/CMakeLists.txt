install(FILES
            pam_wrapper.1
        DESTINATION
            ${MAN_INSTALL_DIR}/man1)

install(FILES
            pam_get_items.8
        DESTINATION
            ${MAN_INSTALL_DIR}/man8)

install(FILES
            pam_set_items.8
        DESTINATION
            ${MAN_INSTALL_DIR}/man8)

#
# Build the documentation
#
include(UseDoxygen OPTIONAL)

