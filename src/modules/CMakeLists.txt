project(pam_wrapper-modules C)

set(PAM_MODULES pam_matrix pam_get_items pam_set_items)

set(PAM_LIBRARIES pam)
if (HAVE_PAM_MISC)
	list(APPEND PAM_LIBRARIES pam_misc)
endif (HAVE_PAM_MISC)

set(PWRAP_PRIVATE_LIBRARIES
	${LIB_INSTALL_DIR}/pam_wrapper)

foreach(_PAM_MODULE ${PAM_MODULES})
	add_library(${_PAM_MODULE} MODULE ${_PAM_MODULE}.c)
	set_property(TARGET ${_PAM_MODULE} PROPERTY PREFIX "")

	target_link_libraries(${_PAM_MODULE}
				${PAM_LIBRARIES})

	install(
		TARGETS
			${_PAM_MODULE}
		LIBRARY DESTINATION ${PWRAP_PRIVATE_LIBRARIES}
		ARCHIVE DESTINATION ${PWRAP_PRIVATE_LIBRARIES})
endforeach()

