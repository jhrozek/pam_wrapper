#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

#define HOME_VAR	"HOMEDIR"
#define HOME_VAR_SZ	sizeof(HOME_VAR)-1

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

struct pam_lib_items {
	const char *username;
	const char *service;
	char *password;
};

struct pam_example_mod_items {
	char *password;
	char *service;
};

struct pam_example_ctx {
	struct pam_lib_items pli;
	struct pam_example_mod_items pmi;
};


static int pam_example_mod_items_get(const char *username,
				     struct pam_example_mod_items *pmi)
{
	int rv;
	const char *db;
	FILE *fp = NULL;
	char buf[BUFSIZ];
	char *file_user = NULL;
	char *file_password = NULL;
	char *file_svc = NULL;

	db = getenv("PWRAP_PASSDB");
	if (db == NULL) {
		rv = EIO;
		goto fail;
	}

	fp = fopen(db, "r");
	if (fp == NULL) {
		rv = errno;
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

		/* Find the user, his password and allowed service */
		NEXT_KEY(file_user, file_password);
		NEXT_KEY(file_password, file_svc);

		q = file_svc;
		while(q[0] != '\n' && q[0] != '\0') {
			q++;
		}
		q[0] = '\0';

		if (file_password == NULL) {
			continue;
		}

		if (strcmp(file_user, username) == 0) {
			pmi->password = strdup(file_password);
			if (pmi->password == NULL) {
				rv = errno;
				goto fail;
			}

			pmi->service = strdup(file_svc);
			if (pmi->service == NULL) {
				rv = errno;
				goto fail;
			}

			break;
		}
	}

	return 0;

fail:
	free(pmi->password);
	free(pmi->service);
	if (fp) {
		fclose(fp);
	}
	return rv;
}

static void pam_example_mod_items_free(struct pam_example_mod_items *pmi)
{
	if (pmi == NULL) {
		return;
	}

	free(pmi->password);
	free(pmi->service);
}

static int pam_lib_items_get(pam_handle_t *pamh,
			     struct pam_lib_items *pli)
{
	int rv;

	rv = pam_get_item(pamh, PAM_USER, (const void **) &(pli->username));
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (pli->username == NULL) {
		return PAM_BAD_ITEM;
	}

	rv = pam_get_item(pamh, PAM_SERVICE, (const void **) &(pli->service));
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	rv = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
			&pli->password, "%s", "Password");
	if (rv != PAM_SUCCESS) {
		return rv;
	}

	if (pli->password == NULL) {
		return PAM_AUTHINFO_UNAVAIL;
	}

	return PAM_SUCCESS;
}

static int pam_example_get(pam_handle_t *pamh, struct pam_example_ctx *pe_ctx)
{
    int rv;

    rv = pam_lib_items_get(pamh, &pe_ctx->pli);
    if (rv != PAM_SUCCESS) {
	    return rv;
    }

    rv = pam_example_mod_items_get(pe_ctx->pli.username, &pe_ctx->pmi);
    if (rv != PAM_SUCCESS) {
	    return rv;
    }

    return PAM_SUCCESS;
}

static void pam_example_free(struct pam_example_ctx *pe_ctx)
{
	pam_example_mod_items_free(&pe_ctx->pmi);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	struct pam_example_ctx pctx;
	int rv;

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	if (strcmp(pctx.pli.password, pctx.pmi.password) == 0) {
		rv = PAM_SUCCESS;
		goto done;
	}

	rv = PAM_AUTH_ERR;
done:
	pam_example_free(&pctx);
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
	struct pam_example_ctx pctx;
	int rv;

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	if (strcmp(pctx.pli.service, pctx.pmi.service) == 0) {
		rv = PAM_SUCCESS;
		goto done;
	}

	rv = PAM_PERM_DENIED;
done:
	pam_example_free(&pctx);
	return rv;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	struct pam_example_ctx pctx;
	int rv;
	char home[PATH_MAX + HOME_VAR_SZ];

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = snprintf(home, sizeof(home),
		      "%s=/home/%s",
		      HOME_VAR, pctx.pli.username);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	rv = pam_putenv(pamh, home);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_example_free(&pctx);
	return rv;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	struct pam_example_ctx pctx;
	int rv;

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_putenv(pamh, HOME_VAR);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_example_free(&pctx);
	return rv;
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
