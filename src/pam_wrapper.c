/*
 * Copyright (c) 2015 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>
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
#include <libgen.h>

#include <ftw.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>
#include <security/pam_ext.h>

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

#define LIBPAM_NAME "libpam.so.0"

typedef int (*__libpam_pam_start)(const char *service_name,
				  const char *user,
				  const struct pam_conv *pam_conversation,
				  pam_handle_t **pamh);

typedef int (*__libpam_pam_end)(pam_handle_t *pamh, int pam_status);

typedef int (*__libpam_pam_authenticate)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_chauthtok)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_acct_mgmt)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_putenv)(pam_handle_t *pamh, const char *name_value);

typedef const char * (*__libpam_pam_getenv)(pam_handle_t *pamh, const char *name);

typedef char ** (*__libpam_pam_getenvlist)(pam_handle_t *pamh);

typedef int (*__libpam_pam_open_session)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_close_session)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_setcred)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_get_item)(const pam_handle_t *pamh,
				     int item_type,
				     const void **item);

typedef int (*__libpam_pam_set_item)(pam_handle_t *pamh,
				     int item_type,
				     const void *item);

typedef int (*__libpam_pam_get_data)(const pam_handle_t *pamh,
				     const char *module_data_name,
				     const void **data);

typedef int (*__libpam_pam_set_data)(pam_handle_t *pamh,
				     const char *module_data_name,
				     void *data,
				     void (*cleanup)(pam_handle_t *pamh,
						     void *data,
						     int error_status));

typedef int (*__libpam_pam_vprompt)(pam_handle_t *pamh,
				    int style,
				    char **response,
				    const char *fmt,
				    va_list args);

typedef const char * (*__libpam_pam_strerror)(pam_handle_t *pamh, int errnum);

typedef void (*__libpam_pam_vsyslog)(const pam_handle_t *pamh,
				     int priority,
				     const char *fmt,
				     va_list args);

#define PWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libpam_##i f; \
		void *obj; \
	} _libpam_##i

struct pwrap_libpam_symbols {
	PWRAP_SYMBOL_ENTRY(pam_start);
	PWRAP_SYMBOL_ENTRY(pam_end);
	PWRAP_SYMBOL_ENTRY(pam_authenticate);
	PWRAP_SYMBOL_ENTRY(pam_chauthtok);
	PWRAP_SYMBOL_ENTRY(pam_acct_mgmt);
	PWRAP_SYMBOL_ENTRY(pam_putenv);
	PWRAP_SYMBOL_ENTRY(pam_getenv);
	PWRAP_SYMBOL_ENTRY(pam_getenvlist);
	PWRAP_SYMBOL_ENTRY(pam_open_session);
	PWRAP_SYMBOL_ENTRY(pam_close_session);
	PWRAP_SYMBOL_ENTRY(pam_setcred);
	PWRAP_SYMBOL_ENTRY(pam_get_item);
	PWRAP_SYMBOL_ENTRY(pam_set_item);
	PWRAP_SYMBOL_ENTRY(pam_get_data);
	PWRAP_SYMBOL_ENTRY(pam_set_data);
	PWRAP_SYMBOL_ENTRY(pam_vprompt);
	PWRAP_SYMBOL_ENTRY(pam_strerror);
	PWRAP_SYMBOL_ENTRY(pam_vsyslog);
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

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case PWRAP_LIBPAM:
		handle = pwrap.libpam.handle;
		if (handle == NULL) {
			char libpam_path[PATH_MAX];

			snprintf(libpam_path,
				 sizeof(libpam_path),
				 "%s/%s",
				 pwrap.config_dir, LIBPAM_NAME);

			handle = dlopen(libpam_path, flags);
			if (handle != NULL) {
				break;
		}

			pwrap.libpam.handle = handle;
		}
		break;
	}

	if (handle == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
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

static int libpam_pam_authenticate(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_authenticate);

	return pwrap.libpam.symbols._libpam_pam_authenticate.f(pamh, flags);
}

static int libpam_pam_chauthtok(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_chauthtok);

	return pwrap.libpam.symbols._libpam_pam_chauthtok.f(pamh, flags);
}

static int libpam_pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_acct_mgmt);

	return pwrap.libpam.symbols._libpam_pam_acct_mgmt.f(pamh, flags);
}

static int libpam_pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	pwrap_bind_symbol_libpam(pam_putenv);

	return pwrap.libpam.symbols._libpam_pam_putenv.f(pamh, name_value);
}

static const char *libpam_pam_getenv(pam_handle_t *pamh, const char *name)
{
	pwrap_bind_symbol_libpam(pam_getenv);

	return pwrap.libpam.symbols._libpam_pam_getenv.f(pamh, name);
}

static char **libpam_pam_getenvlist(pam_handle_t *pamh)
{
	pwrap_bind_symbol_libpam(pam_getenvlist);

	return pwrap.libpam.symbols._libpam_pam_getenvlist.f(pamh);
}

static int libpam_pam_open_session(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_open_session);

	return pwrap.libpam.symbols._libpam_pam_open_session.f(pamh, flags);
}

static int libpam_pam_close_session(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_close_session);

	return pwrap.libpam.symbols._libpam_pam_close_session.f(pamh, flags);
}

static int libpam_pam_setcred(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_setcred);

	return pwrap.libpam.symbols._libpam_pam_setcred.f(pamh, flags);
}

static int libpam_pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	pwrap_bind_symbol_libpam(pam_get_item);

	return pwrap.libpam.symbols._libpam_pam_get_item.f(pamh, item_type, item);
}

static int libpam_pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	pwrap_bind_symbol_libpam(pam_set_item);

	return pwrap.libpam.symbols._libpam_pam_set_item.f(pamh, item_type, item);
}

static int libpam_pam_get_data(const pam_handle_t *pamh,
			       const char *module_data_name,
			       const void **data)
{
	pwrap_bind_symbol_libpam(pam_get_data);

	return pwrap.libpam.symbols._libpam_pam_get_data.f(pamh,
							   module_data_name,
							   data);
}

static int libpam_pam_set_data(pam_handle_t *pamh,
			       const char *module_data_name,
			       void *data,
			       void (*cleanup)(pam_handle_t *pamh,
					       void *data,
					       int error_status))
{
	pwrap_bind_symbol_libpam(pam_set_data);

	return pwrap.libpam.symbols._libpam_pam_set_data.f(pamh,
							   module_data_name,
							   data,
							   cleanup);
}

static int libpam_pam_vprompt(pam_handle_t *pamh,
			      int style,
			      char **response,
			      const char *fmt,
			      va_list args)
{
	pwrap_bind_symbol_libpam(pam_vprompt);

	return pwrap.libpam.symbols._libpam_pam_vprompt.f(pamh,
							  style,
							  response,
							  fmt,
							  args);
}

static const char *libpam_pam_strerror(pam_handle_t *pamh, int errnum)
{
	pwrap_bind_symbol_libpam(pam_strerror);

	return pwrap.libpam.symbols._libpam_pam_strerror.f(pamh, errnum);
}

static void libpam_pam_vsyslog(const pam_handle_t *pamh,
			       int priority,
			       const char *fmt,
			       va_list args)
{
	pwrap_bind_symbol_libpam(pam_vsyslog);

	pwrap.libpam.symbols._libpam_pam_vsyslog.f(pamh,
						   priority,
						   fmt,
						   args);
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

static int copy_ftw(const char *fpath,
		    const struct stat *sb,
		    int typeflag,
		    struct FTW *ftwbuf)
{
	int rc;
	char buf[BUFFER_SIZE];

	switch (typeflag) {
	case FTW_D:
	case FTW_DNR:
		/* We want to copy the directories from this directory */
		if (ftwbuf->level == 0) {
			return FTW_CONTINUE;
		}
		return FTW_SKIP_SUBTREE;
	case FTW_F:
		break;
	default:
		return FTW_CONTINUE;
	}

	rc = snprintf(buf, BUFFER_SIZE, "%s/%s", pwrap.config_dir, fpath + ftwbuf->base);
	if (rc >= BUFFER_SIZE) {
		return FTW_STOP;
	}

	PWRAP_LOG(PWRAP_LOG_TRACE, "Copying %s", fpath);
	rc = p_copy(fpath, buf, NULL, sb->st_mode);
	if (rc != 0) {
		return FTW_STOP;
	}

	return FTW_CONTINUE;
}

static int copy_confdir(const char *src)
{
	int rc;

	PWRAP_LOG(PWRAP_LOG_DEBUG,
		  "Copy config files from %s to %s",
		  src,
		  pwrap.config_dir);
	rc = nftw(src, copy_ftw, 1, FTW_ACTIONRETVAL);
	if (rc != 0) {
		return -1;
	}

	return 0;
}

static void pwrap_init(void)
{
	char tmp_config_dir[] = "/tmp/pam.X";
	size_t len = strlen(tmp_config_dir);
	const char *env;
	uint32_t i;
	int rc;
	char pam_library[128] = { 0 };
	char pam_path[1024] = { 0 };
	ssize_t ret;

	if (!pam_wrapper_enabled()) {
		return;
	}

	if (pwrap.initialised) {
		return;
	}

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Initialize pam_wrapper");

	for (i = 0; i < 36; i++) {
		struct stat sb;
		char c;

		if (i < 10) {
			c = (char)(i + 48);
		} else {
			c = (char)(i + 87);
		}

		tmp_config_dir[len - 1] = c;
		rc = lstat(tmp_config_dir, &sb);
		if (rc == 0) {
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "Check pam_wrapper dir %s already exists",
				  tmp_config_dir);
			continue;
		} else if (errno == ENOENT) {
			break;
		}
	}

	if (i == 36) {
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

	/* copy libpam.so.0 */
	snprintf(pam_path, sizeof(pam_path), "%s", PAM_LIBRARY);
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

	if (pam_library[0] == '/') {
		snprintf(pam_path,
			 sizeof(pam_path),
			 "%s",
			 pam_library);
	} else {
		char pam_path_cp[sizeof(pam_path)];
		char *dname;

		strncpy(pam_path_cp, pam_path, sizeof(pam_path_cp));

		dname = dirname(pam_path_cp);
		if (dname == NULL) {
			PWRAP_LOG(PWRAP_LOG_ERROR,
				  "No directory component in %s", pam_path);
			exit(1);
		}

		snprintf(pam_path,
			 sizeof(pam_path),
			 "%s/%s",
			 dname,
			 pam_library);
	}
	PWRAP_LOG(PWRAP_LOG_TRACE, "Reconstructed PAM path: %s", pam_path);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Copy %s to %s", pam_path, pwrap.pam_library);
	rc = p_copy(pam_path, pwrap.pam_library, pwrap.config_dir, 0644);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to copy %s - error: %s",
			  LIBPAM_NAME,
			  strerror(errno));
		exit(1);
	}

	/* modify libpam.so */

	pwrap.initialised = true;

	env = getenv("PAM_WRAPPER_CONFDIR");
	if (env == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No config file");
		exit(1);
	}

	rc = copy_confdir(env);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to copy config files");
		exit(1);
	}

	setenv("PWRAP_TEST_CONF_DIR", pwrap.config_dir, 1);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Successfully initialized pam_wrapper");
}

bool pam_wrapper_enabled(void)
{
	const char *env;

	pwrap.enabled = false;

	env = getenv("PAM_WRAPPER");
	if (env != NULL && env[0] == '1') {
		pwrap.enabled = true;
	}

	if (pwrap.enabled) {
		pwrap.enabled = false;

		env = getenv("PAM_WRAPPER_CONFDIR");
		if (env != NULL && env[0] != '\0') {
			pwrap.enabled = true;
		}
	}

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


static int pwrap_pam_start(const char *service_name,
			   const char *user,
			   const struct pam_conv *pam_conversation,
			   pam_handle_t **pamh)
{
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pam_start service=%s, user=%s",
		  service_name,
		  user);

	return libpam_pam_start(service_name,
				user,
				pam_conversation,
				pamh);
}


int pam_start(const char *service_name,
	      const char *user,
	      const struct pam_conv *pam_conversation,
	      pam_handle_t **pamh)
{
	return pwrap_pam_start(service_name, user, pam_conversation, pamh);
}

static int pwrap_pam_end(pam_handle_t *pamh, int pam_status)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_end status=%d", pam_status);
	return libpam_pam_end(pamh, pam_status);
}


int pam_end(pam_handle_t *pamh, int pam_status)
{
	return pwrap_pam_end(pamh, pam_status);
}

static int pwrap_pam_authenticate(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_authenticate flags=%d", flags);
	return libpam_pam_authenticate(pamh, flags);
}

int pam_authenticate(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_authenticate(pamh, flags);
}

static int pwrap_pam_chauthtok(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_chauthtok flags=%d", flags);
	return libpam_pam_chauthtok(pamh, flags);
}

int pam_chauthtok(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_chauthtok(pamh, flags);
}

static int pwrap_pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_acct_mgmt flags=%d", flags);
	return libpam_pam_acct_mgmt(pamh, flags);
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_acct_mgmt(pamh, flags);
}

static int pwrap_pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_putenv name_value=%s", name_value);
	return libpam_pam_putenv(pamh, name_value);
}

int pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	return pwrap_pam_putenv(pamh, name_value);
}

static const char *pwrap_pam_getenv(pam_handle_t *pamh, const char *name)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_getenv name=%s", name);
	return libpam_pam_getenv(pamh, name);
}

const char *pam_getenv(pam_handle_t *pamh, const char *name)
{
	return pwrap_pam_getenv(pamh, name);
}

static char **pwrap_pam_getenvlist(pam_handle_t *pamh)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_getenvlist called");
	return libpam_pam_getenvlist(pamh);
}

char **pam_getenvlist(pam_handle_t *pamh)
{
	return pwrap_pam_getenvlist(pamh);
}

static int pwrap_pam_open_session(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_open_session flags=%d", flags);
	return libpam_pam_open_session(pamh, flags);
}

int pam_open_session(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_open_session(pamh, flags);
}

static int pwrap_pam_close_session(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_close_session flags=%d", flags);
	return libpam_pam_close_session(pamh, flags);
}

int pam_close_session(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_close_session(pamh, flags);
}

static int pwrap_pam_setcred(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_setcred flags=%d", flags);
	return libpam_pam_setcred(pamh, flags);
}

int pam_setcred(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_setcred(pamh, flags);
}

static int pwrap_pam_get_item(const pam_handle_t *pamh,
			      int item_type,
			      const void **item)
{
	int rc;

	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_get_item called");

	rc = libpam_pam_get_item(pamh, item_type, item);

	if (rc == PAM_SUCCESS) {
		switch(item_type) {
		case PAM_USER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER=%s",
				  (char *)item);
			break;
		case PAM_SERVICE:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_SERVICE=%s",
				  (char *)item);
			break;
		case PAM_USER_PROMPT:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER_PROMPT=%s",
				  (char *)item);
			break;
		case PAM_TTY:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_TTY=%s",
				  (char *)item);
			break;
		case PAM_RUSER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RUSER=%s",
				  (char *)item);
			break;
		case PAM_RHOST:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RHOST=%s",
				  (char *)item);
			break;
		case PAM_AUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_AUTHTOK=%s",
				  (char *)item);
			break;
		case PAM_OLDAUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_OLDAUTHTOK=%s",
				  (char *)item);
			break;
		case PAM_CONV:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_CONV=%p",
				  (void *) item);
			break;
		default:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item item_type=%d item=%p",
				  item_type, (void *) item);
			break;
		}
	} else {
		PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_get_item failed rc=%d", rc);
	}

	return rc;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	return pwrap_pam_get_item(pamh, item_type, item);
}

static int pwrap_pam_set_item(pam_handle_t *pamh,
			      int item_type,
			      const void *item)
{
	int rc;

	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_set_item called");

	rc = libpam_pam_set_item(pamh, item_type, item);
	if (rc == PAM_SUCCESS) {
		switch(item_type) {
		case PAM_USER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER=%s",
				  (char *)item);
			break;
		case PAM_SERVICE:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_SERVICE=%s",
				  (char *)item);
			break;
		case PAM_USER_PROMPT:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER_PROMPT=%s",
				  (char *)item);
			break;
		case PAM_TTY:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_TTY=%s",
				  (char *)item);
			break;
		case PAM_RUSER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RUSER=%s",
				  (char *)item);
			break;
		case PAM_RHOST:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RHOST=%s",
				  (char *)item);
			break;
		case PAM_AUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_AUTHTOK=%s",
				  (char *)item);
			break;
		case PAM_OLDAUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_OLDAUTHTOK=%s",
				  (char *)item);
			break;
		case PAM_CONV:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_CONV=%p",
				  item);
			break;
		default:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item item_type=%d item=%p",
				  item_type, item);
			break;
		}
	} else {
		PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_set_item failed rc=%d", rc);
	}

	return rc;
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	return pwrap_pam_set_item(pamh, item_type, item);
}

static int pwrap_pam_get_data(const pam_handle_t *pamh,
			      const char *module_data_name,
			      const void **data)
{
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pwrap_get_data module_data_name=%s", module_data_name);
	return libpam_pam_get_data(pamh, module_data_name, data);
}

int pam_get_data(const pam_handle_t *pamh,
		 const char *module_data_name,
		 const void **data)
{
	return pwrap_pam_get_data(pamh, module_data_name, data);
}

static int pwrap_pam_set_data(pam_handle_t *pamh,
			      const char *module_data_name,
			      void *data,
			      void (*cleanup)(pam_handle_t *pamh,
					      void *data,
					      int error_status))
{
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pwrap_set_data module_data_name=%s data=%p",
		  module_data_name, data);
	return libpam_pam_set_data(pamh, module_data_name, data, cleanup);
}

int pam_set_data(pam_handle_t *pamh,
		 const char *module_data_name,
		 void *data,
		 void (*cleanup)(pam_handle_t *pamh,
				 void *data,
				 int error_status))
{
	return pwrap_pam_set_data(pamh, module_data_name, data, cleanup);
}

static int pwrap_pam_vprompt(pam_handle_t *pamh,
			     int style,
			     char **response,
			     const char *fmt,
			     va_list args)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_vprompt style=%d", style);
	return libpam_pam_vprompt(pamh, style, response, fmt, args);
}

int pam_vprompt(pam_handle_t *pamh,
		int style,
		char **response,
		const char *fmt,
		va_list args)
{
	return pwrap_pam_vprompt(pamh, style, response, fmt, args);
}

int pam_prompt(pam_handle_t *pamh,
	       int style,
	       char **response,
	       const char *fmt, ...)
{
	va_list args;
	int rv;

	va_start(args, fmt);
	rv = pwrap_pam_vprompt(pamh, style, response, fmt, args);
	va_end(args);

	return rv;  
}

static const char *pwrap_pam_strerror(pam_handle_t *pamh, int errnum)
{
	const char *str;
	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_strerror errnum=%d", errnum);

	str = libpam_pam_strerror(pamh, errnum);

	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_strerror error=%s", str);

	return str;
}

const char *pam_strerror(pam_handle_t *pamh, int errnum)
{
	return pwrap_pam_strerror(pamh, errnum);
}

static void pwrap_pam_vsyslog(const pam_handle_t *pamh,
			      int priority,
			      const char *fmt,
			      va_list args)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_vsyslog called");
	libpam_pam_vsyslog(pamh, priority, fmt, args);
}

void pam_vsyslog(const pam_handle_t *pamh,
		 int priority,
		 const char *fmt,
		 va_list args)
{
	pwrap_pam_vsyslog(pamh, priority, fmt, args);
}

void pam_syslog(const pam_handle_t *pamh,
	        int priority,
	        const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	pwrap_pam_vsyslog(pamh, priority, fmt, args);
	va_end(args);
}

/****************************
 * DESTRUCTOR
 ***************************/

static int p_rmdirs(const char *path) {
	DIR *d;
	struct dirent *dp;
	struct stat sb;
	char *fname;

	return 0;

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

	if (!pwrap.initialised) {
		return;
	}

	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "destructor called for pam_wrapper dir %s",
		  pwrap.config_dir);
	env = getenv("PAM_WRAPPER_KEEP_DIR");
	if (env == NULL || env[0] != '1') {
		p_rmdirs(pwrap.config_dir);
	}
}
