#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

/* Skips leading tabs and spaces to find beginning of a key,
 * then walks over the key until a blank is find
 */
#define NEXT_KEY(buf, key) do {					\
	(key) = (buf) ? strpbrk((buf), " \t") : NULL;		\
	if ((key) != NULL) {					\
		(key)[0] = '\0';				\
		(key)++;					\
	}							\
	while ((key) != NULL					\
	       && (isblank((int)(key)[0]))) {			\
		(key)++;					\
	}							\
} while(0);

struct pam_items {
	const char *username;
	char *pam_password;

	char *password;
};

static char *find_password(const char *username)
{
	const char *db;
	char *passwd = NULL;
	FILE *fp = NULL;
	char buf[BUFSIZ];
	char *file_user = NULL;
	char *file_password = NULL;

	db = getenv("PWRAP_PASSDB");
	if (db == NULL) {
		goto fail;
	}

	fp = fopen(db, "r");
	if (fp == NULL) {
		goto fail;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *q;

		file_user = buf;
		file_password = NULL;

		/* Skip comments */
		if (file_user[0] == '#') {
			continue;
		}

		/* Find the user */
		NEXT_KEY(file_user, file_password);

		q = file_password;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (file_password == NULL) {
			continue;
		}

		if (strcmp(file_user, username) == 0) {
			passwd = strdup(file_password);
			if (passwd == NULL) {
				goto fail;
			}
			break;
		}
	}

	return passwd;

fail:
	free(passwd);
	if (fp) fclose(fp);
	return NULL;
}

static int get_info(pam_handle_t *pamh, struct pam_items *pi)
{
	int rv;

	rv = pam_get_item(pamh, PAM_USER, (const void **) &(pi->username));
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (pi->username == NULL) {
		return PAM_BAD_ITEM;
	}

	rv = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
			&pi->pam_password, "%s", "Password");
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (pi->pam_password == NULL) {
		return PAM_AUTHINFO_UNAVAIL;
	}

	pi->password = find_password(pi->username);
	if (pi->password == NULL) {
		return PAM_USER_UNKNOWN;
	}

	return PAM_SUCCESS;
}

static void pam_items_free(struct pam_items *pi)
{
	if (pi == NULL) {
		return;
	}

	free(pi->password);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	struct pam_items pi;
	int rv;

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pi, 0, sizeof(struct pam_items));

	rv = get_info(pamh, &pi);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	if (strcmp(pi.pam_password, pi.password) == 0) {
		rv = PAM_SUCCESS;
		goto done;
	}

	rv = PAM_AUTH_ERR;
done:
	pam_items_free(&pi);
	return rv;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
	(void) pamh;  /* unused */
	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) pamh;  /* unused */
	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	(void) pamh;  /* unused */
	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	(void) pamh;  /* unused */
	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	(void) pamh;  /* unused */
	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	return PAM_SERVICE_ERR;
}
