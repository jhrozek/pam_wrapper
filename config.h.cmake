/* Name of package */
#cmakedefine PACKAGE "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine VERSION "${APPLICATION_VERSION}"

#cmakedefine LOCALEDIR "${LOCALE_INSTALL_DIR}"
#cmakedefine DATADIR "${DATADIR}"
#cmakedefine LIBDIR "${LIBDIR}"
#cmakedefine PLUGINDIR "${PLUGINDIR}"
#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

#cmakedefine HAVE_SYS_TYPES_H 1
#cmakedefine HAVE_UNISTD_H 1
#cmakedefine HAVE_SECURITY_PAM_APPL_H 1
#cmakedefine HAVE_SECURITY_PAM_MODULES_H 1
#cmakedefine HAVE_SECURITY_PAM_EXT_H 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `seteuid' function. */
#cmakedefine HAVE_SETEUID 1

/*************************** LIBRARIES ***************************/
#cmakedefine PAM_LIBRARY "${PAM_LIBRARY}"

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_APPLE 1

#cmakedefine HAVE_GCC_THREAD_LOCAL_STORAGE 1
#cmakedefine HAVE_GCC_ATOMIC_BUILTINS 1
#cmakedefine HAVE_CONSTRUCTOR_ATTRIBUTE 1
#cmakedefine HAVE_DESTRUCTOR_ATTRIBUTE 1
#cmakedefine HAVE_FUNCTION_ATTRIBUTE_FORMAT 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
