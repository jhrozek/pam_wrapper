/*
 * Copyright (c) 2009      Andrew Tridgell
 * Copyright (c) 2011-2013 Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define PWRAP_THREAD __thread
#else
# define PWRAP_THREAD
#endif

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

#ifdef HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE __attribute__((no_sanitize_address))
#else /* DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE */
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
#endif /* DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE */

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

/*****************
 * LOGGING
 *****************/

enum pwrap_dbglvl_e {
	PWRAP_LOG_ERROR = 0,
	PWRAP_LOG_WARN,
	PWRAP_LOG_DEBUG,
	PWRAP_LOG_TRACE
};

#ifdef NDEBUG
# define PWRAP_LOG(...)
#else /* NDEBUG */
static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define PWRAP_LOG(dbglvl, ...) pwrap_log((dbglvl), __func__, __VA_ARGS__)

static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;

	d = getenv("PAM_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		const char *prefix = "PWRAP";
		switch (dbglvl) {
			case PWRAP_LOG_ERROR:
				prefix = "PWRAP_ERROR";
				break;
			case PWRAP_LOG_WARN:
				prefix = "PWRAP_WARN";
				break;
			case PWRAP_LOG_DEBUG:
				prefix = "PWRAP_DEBUG";
				break;
			case PWRAP_LOG_TRACE:
				prefix = "PWRAP_TRACE";
				break;
		}

		fprintf(stderr,
			"%s(%d) - %s: %s\n",
			prefix,
			(int)getpid(),
			function,
			buffer);
	}
}
#endif /* NDEBUG */

/*****************
 * LIBC
 *****************/

#define LIBPAM_NAME "libpam.so"

typedef int (*__libpam_pam_start)(const char *service_name,
				  const char *user,
				  const struct pam_conv *pam_conversation,
				  pam_handle_t **pamh);

typedef int (*__libpam_pam_end)(pam_handle_t *pamh, int pam_status);

#define PWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libpam_##i f; \
		void *obj; \
	} _libpam_##i

struct pwrap_libpam_symbols {
	PWRAP_SYMBOL_ENTRY(pam_start);
	PWRAP_SYMBOL_ENTRY(pam_end);
};

struct pwrap {
	struct {
		void *handle;
		struct pwrap_libpam_symbols symbols;
	} libpam;

	bool enabled;
	bool initialised;
	char *config_dir;
};

static struct pwrap pwrap;

/*********************************************************
 * PWRAP PROTOTYPES
 *********************************************************/

bool pam_wrapper_enabled(void);
void pwrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
void pwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * PWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum pwrap_lib {
    PWRAP_LIBPAM,
};

static void *pwrap_load_lib_handle(enum pwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case PWRAP_LIBPAM:
		handle = pwrap.libpam.handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				handle = dlopen(LIBPAM_NAME, flags);
				if (handle != NULL) {
					break;
				}
			}

			pwrap.libpam.handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = pwrap.libpam.handle = RTLD_NEXT;
#else
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_pwrap_bind_symbol(enum pwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = pwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to find %s: %s\n",
			  fn_name, dlerror());
		exit(-1);
	}

	return func;
}

#define pwrap_bind_symbol_libpam(sym_name) \
	if (pwrap.libpam.symbols._libpam_##sym_name.obj == NULL) { \
		pwrap.libpam.symbols._libpam_##sym_name.obj = \
			_pwrap_bind_symbol(PWRAP_LIBPAM, #sym_name); \
	} \

/*
 * IMPORTANT
 *
 * Functions especially from libpam need to be loaded individually, you can't
 * load all at once or gdb will segfault at startup. The same applies to
 * valgrind and has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
static int libpam_pam_start(const char *service_name,
			    const char *user,
			    const struct pam_conv *pam_conversation,
			    pam_handle_t **pamh)
{
	pwrap_bind_symbol_libpam(pam_start);

	return pwrap.libpam.symbols._libpam_pam_start.f(service_name,
							user,
							pam_conversation,
							pamh);
}

static int libpam_pam_end(pam_handle_t *pamh, int pam_status)
{
	pwrap_bind_symbol_libpam(pam_end);

	return pwrap.libpam.symbols._libpam_pam_end.f(pamh, pam_status);
}

/*********************************************************
 * PWRAP INIT
 *********************************************************/

static void pwrap_init(void)
{
	char tmp_config_dir[] = "/tmp/pamd.X";
	size_t len = strlen(tmp_config_dir);
	const char *env;
	uint32_t i;
	int rc;

	if (pwrap.initialised) {
		return;
	}

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Initialize pam_wrapper");

	for (i = 0; i < 10; i++) {
		struct stat sb;

		tmp_config_dir[len - 1] = (char)(i + 48);
		PWRAP_LOG(PWRAP_LOG_TRACE,
			  "Check pam_wrapper dir %s already exists",
			  tmp_config_dir);
		rc = lstat(tmp_config_dir, &sb);
		if (rc == 0) {
			continue;
		} else if (errno == ENOENT) {
			break;
		}
	}

	if (i == 10) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to find a possible path to create pam_wrapper config dir: %s",
			  tmp_config_dir);
		exit(1);
	}

	pwrap.config_dir = strdup(tmp_config_dir);
	if (pwrap.config_dir == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "No memory");
		exit(1);
	}
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pam_wrapper config dir: %s",
		  tmp_config_dir);

	rc = mkdir(pwrap.config_dir, 0755);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to create pam_wrapper config dir: %s - %s",
			  tmp_config_dir, strerror(errno));
	}

	pwrap.initialised = true;

	env = getenv("PAM_WRAPPER");
	if (env != NULL && env[0] == '1') {

		pwrap.enabled = true;
	}

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Succeccfully initialized pam_wrapper");
}

bool pam_wrapper_enabled(void)
{
	return pwrap.enabled;
}

/****************************
 * CONSTRUCTOR
 ***************************/
void pwrap_constructor(void)
{
	/*
	 * Here is safe place to call pwrap_init() and initialize data
	 * for main process.
	 */
	pwrap_init();
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * resources are freed.
 */
void pwrap_destructor(void)
{
	if (pwrap.libpam.handle != NULL) {
		dlclose(pwrap.libpam.handle);
	}
}
