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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include "pwrap_compat.h"

static const char *str_opt(const int opt)
{
	switch (opt) {
	case PAM_SERVICE:
		return "PAM_SERVICE";
	case PAM_USER:
		return "PAM_USER";
	case PAM_USER_PROMPT:
		return "PAM_USER_PROMPT";
	case PAM_TTY:
		return "PAM_TTY";
	case PAM_RUSER:
		return "PAM_RUSER";
	case PAM_RHOST:
		return "PAM_RHOST";
	case PAM_AUTHTOK:
		return "PAM_AUTHTOK";
	case PAM_OLDAUTHTOK:
		return "PAM_OLDAUTHTOK";
#ifdef PAM_XDISPLAY
	case PAM_XDISPLAY:
		return "PAM_XDISPLAY";
#endif
#ifdef PAM_AUTHTOK_TYPE
	case PAM_AUTHTOK_TYPE:
		return "PAM_AUTHTOK_TYPE";
#endif
	}

	return NULL;	/* Unsupported */
}

static int putenv_item(pam_handle_t *pamh,
		       int item_type)
{
	const char *opt_name;
	const char *value = NULL;
	char *env_name;
	size_t env_len;
	int rv;

	rv = pam_get_item(pamh, item_type, (const void **) &value);
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (value == NULL) {
		return PAM_SUCCESS;
	}

	opt_name = str_opt(item_type);
	if (opt_name == NULL) {
		/* Probably some non-printable value */
		return PAM_BAD_ITEM;
	}

	env_len = strlen(value) + strlen(opt_name) + 2;
	env_name = malloc(env_len);
	if (env_name == NULL) {
		return PAM_BUF_ERR;
	}

	rv = snprintf(env_name, env_len, "%s=%s", opt_name, value);
	if (rv < 0) {
		free(env_name);
		return PAM_BUF_ERR;
	}

	rv = pam_putenv(pamh, env_name);
	free(env_name);

	return rv;
}

/* Get all pam_items and put them into environment */
static int pam_putitem(pam_handle_t *pamh)
{

	putenv_item(pamh, PAM_SERVICE);
	putenv_item(pamh, PAM_USER);
	putenv_item(pamh, PAM_USER_PROMPT);
	putenv_item(pamh, PAM_TTY);
	putenv_item(pamh, PAM_RUSER);
	putenv_item(pamh, PAM_RHOST);
	putenv_item(pamh, PAM_AUTHTOK);
	putenv_item(pamh, PAM_OLDAUTHTOK);
#ifdef PAM_XDISPLAY
	putenv_item(pamh, PAM_XDISPLAY);
#endif
#ifdef PAM_AUTHTOK_TYPE
	putenv_item(pamh, PAM_AUTHTOK_TYPE);
#endif

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) flags;	/* unused */
	(void) argc;	/* unused */
	(void) argv;	/* unused */

	return pam_putitem(pamh);
}
