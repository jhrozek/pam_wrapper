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
#include <dirent.h>
#include <fcntl.h>
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
	char *pam_library;
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

#define BUFFER_SIZE 32768

/* copy file from src to dst, overwrites dst */
static int p_copy(const char *src, const char *dst, const char *pdir, mode_t mode)
{
	int srcfd = -1;
	int dstfd = -1;
	int rc = -1;
	ssize_t bread, bwritten;
	struct stat sb;
	char buf[BUFFER_SIZE];
	int cmp;

	cmp = strcmp(src, dst);
	if (cmp == 0) {
		return -1;
	}

	if (lstat(src, &sb) < 0) {
		return -1;
	}

	if (S_ISDIR(sb.st_mode)) {
		errno = EISDIR;
		return -1;
	}

	if (mode == 0) {
		mode = sb.st_mode;
	}

	if (lstat(dst, &sb) == 0) {
		if (S_ISDIR(sb.st_mode)) {
			errno = EISDIR;
			return -1;
		}
	}

	if ((srcfd = open(src, O_RDONLY, 0)) < 0) {
		rc = -1;
		goto out;
	}

	if ((dstfd = open(dst, O_CREAT|O_WRONLY|O_TRUNC, mode)) < 0) {
		rc = -1;
		goto out;
	}

	for (;;) {
		char *p;
		bread = read(srcfd, buf, BUFFER_SIZE);
		if (bread == 0) {
			/* done */
			break;
		} else if (bread < 0) {
			errno = ENODATA;
			rc = -1;
			goto out;
		}

		/* EXTRA UGLY HACK */
		if (pdir != NULL) {
			p = buf;

			while (p < buf + BUFFER_SIZE) {
				if (*p == '/') {
					cmp = memcmp(p, "/etc/pam.d", 10);
					if (cmp == 0) {
						memcpy(p, pdir, 10);
					}
				}
				p++;
			}
		}

		bwritten = write(dstfd, buf, bread);
		if (bwritten < 0) {
			errno = ENODATA;
			rc = -1;
			goto out;
		}

		if (bread != bwritten) {
			errno = EFAULT;
			rc = -1;
			goto out;
		}
	}

	rc = 0;
out:
	close(srcfd);
	close(dstfd);
	if (rc < 0) {
		unlink(dst);
	}

	return rc;
}

static void pwrap_init(void)
{
	char tmp_config_dir[] = "/tmp/pam.X";
	size_t len = strlen(tmp_config_dir);
	const char *env;
	uint32_t i;
	int rc;
	const char *suffix = "";
	char pam_library[128] = { 0 };
	char pam_path[1024] = { 0 };
	ssize_t ret;

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

	snprintf(pam_path,
		 sizeof(pam_path),
		 "%s/%s",
		 pwrap.config_dir,
		 LIBPAM_NAME);

	pwrap.pam_library = strdup(pam_path);
	if (pwrap.pam_library == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No memory");
		exit(1);
	}

	/* copy libpam.so */
	if (sizeof(void *) == 8) {
		suffix = "64";
	}

	snprintf(pam_path,
		 sizeof(pam_path),
		 "/usr/lib%s/%s",
		 suffix,
		 LIBPAM_NAME);
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "PAM path: %s",
		  pam_path);

	ret = readlink(pam_path, pam_library, sizeof(pam_library));
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "PAM library: %s",
		  pam_library);
	if (ret <= 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to read %s link", LIBPAM_NAME);
		exit(1);
	}

	snprintf(pam_path,
		 sizeof(pam_path),
		 "/usr/lib%s/%s",
		 suffix,
		 pam_library);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Copy %s to %s", pam_path, pwrap.pam_library);
	rc = p_copy(pam_path, pwrap.pam_library, pwrap.config_dir, 0644);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to copy %s", LIBPAM_NAME);
		exit(1);
	}

	/* modify libpam.so */

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

static int p_rmdirs(const char *path) {
	DIR *d;
	struct dirent *dp;
	struct stat sb;
	char *fname;

	if ((d = opendir(path)) != NULL) {
		while(stat(path, &sb) == 0) {
			/* if we can remove the directory we're done */
			if (rmdir(path) == 0) {
				break;
			}
			switch (errno) {
				case ENOTEMPTY:
				case EEXIST:
				case EBADF:
					break; /* continue */
				default:
					closedir(d);
					return 0;
			}

			while ((dp = readdir(d)) != NULL) {
				size_t len;
				/* skip '.' and '..' */
				if (dp->d_name[0] == '.' &&
				    (dp->d_name[1] == '\0' ||
				     (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
					continue;
				}

				len = strlen(path) + strlen(dp->d_name) + 2;
				fname = malloc(len);
				if (fname == NULL) {
					return -1;
				}
				snprintf(fname, len, "%s/%s", path, dp->d_name);

				/* stat the file */
				if (lstat(fname, &sb) != -1) {
					if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
						if (rmdir(fname) < 0) { /* can't be deleted */
							if (errno == EACCES) {
								closedir(d);
								SAFE_FREE(fname);
								return -1;
							}
							p_rmdirs(fname);
						}
					} else {
						unlink(fname);
					}
				} /* lstat */
				SAFE_FREE(fname);
			} /* readdir */

			rewinddir(d);
		}
	} else {
		return -1;
	}

	closedir(d);
	return 0;
}

/*
 * This function is called when the library is unloaded and makes sure that
 * resources are freed.
 */
void pwrap_destructor(void)
{
	const char *env;

	if (pwrap.libpam.handle != NULL) {
		dlclose(pwrap.libpam.handle);
	}

	env = getenv("PAM_WRAPPER_KEEP_DIR");
	if (env == NULL || env[0] != '1') {
		p_rmdirs(pwrap.config_dir);
	}
}
