#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

#define HOME_VAR	"HOMEDIR"
#define HOME_VAR_SZ	sizeof(HOME_VAR)-1

#define CRED_VAR	"CRED"
#define CRED_VAR_SZ	sizeof(CRED_VAR)-1

#define PAM_EXAMPLE_AUTH_DATA	    "pam_example:auth_data"

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


#define wipe_authtok(tok) do {		\
	if (tok != NULL) {		\
		char *__tk = tok;	\
		while(*__tk != '\0') {	\
			*__tk = '\0';	\
		}			\
		tok = NULL;		\
	}				\
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
		rv = PAM_AUTHINFO_UNAVAIL;
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

	fclose(fp);
	return 0;

fail:
	free(pmi->password);
	free(pmi->service);
	if (fp) {
		fclose(fp);
	}
	return rv;
}

static int pam_example_lib_items_put(struct pam_lib_items *pli)
{
	int rv;
	const char *db;
	FILE *fp = NULL;
	FILE *fp_tmp = NULL;
	char buf[BUFSIZ];
	char template[PATH_MAX] = { '\0' };
	char *file_user = NULL;
	char *file_password = NULL;
	char *file_svc = NULL;

	db = getenv("PWRAP_PASSDB");
	if (db == NULL) {
		rv = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}

	rv = snprintf(template, sizeof(template),
		      "%s.XXXXXX", db);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	/* We don't support concurrent runs.. */
	rv = mkstemp(template);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	fp = fopen(db, "r");
	fp_tmp = fopen(template, "w");
	if (fp == NULL || fp_tmp == NULL) {
		rv = errno;
		goto done;
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

		if (strcmp(file_user, pli->username) == 0) {
			if (pli->password) {
				file_password = pli->password;
			}
		}

		rv = fprintf(fp_tmp, "%s\t%s\t%s\n",
			     file_user, file_password, file_svc);
		if (rv < 0) {
			rv = PAM_CRED_ERR;
			goto done;
		}
	}

	rv = PAM_SUCCESS;
done:
	if (fp != NULL) {
		fclose(fp);
	}
	if (fp_tmp != NULL) {
		fflush(fp_tmp);
		fclose(fp_tmp);
	}

	if (rv == PAM_SUCCESS) {
		rv = rename(template, db);
		if (rv == -1) {
			rv = PAM_SYSTEM_ERR;
		}
	}

	if (template[0] != '\0') {
		unlink(template);
	};
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

static int pam_example_read_password(pam_handle_t *pamh,
				     int authtok_item,
				     const char *prompt1,
				     const char *prompt2,
				     const void **_out_tok)
{
	int rv = PAM_AUTHTOK_RECOVERY_ERR;
	char *authtok1 = NULL;
	char *authtok2 = NULL;
	const void *item;

	rv = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
			&authtok1, "%s", prompt1);
	if (authtok1 == NULL) {
		goto done;
	}

	if (rv == PAM_SUCCESS && prompt2 != NULL) {
		rv = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
				&authtok2, "%s", prompt2);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		if (authtok2 == NULL) {
			rv = PAM_AUTHTOK_RECOVERY_ERR;
			goto done;
		}

		if (strcmp(authtok1, authtok2) != 0) {
			pam_prompt(pamh, PAM_ERROR_MSG, NULL,
				   "%s", "Passwords do not match");
			rv = PAM_AUTHTOK_RECOVERY_ERR;
			goto done;
		}
		wipe_authtok(authtok2);
	}

	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_set_item(pamh, authtok_item, authtok1);
	wipe_authtok(authtok1);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = pam_get_item(pamh, authtok_item, &item);
	if (_out_tok) {
		*_out_tok = item;
	}
	item = NULL;
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	wipe_authtok(authtok1);
	wipe_authtok(authtok2);
	return rv;
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
		return PAM_AUTHINFO_UNAVAIL;
    }

    return PAM_SUCCESS;
}

static void pam_example_free(struct pam_example_ctx *pe_ctx)
{
	pam_example_mod_items_free(&pe_ctx->pmi);
}

static int _pam_example_auth(struct pam_example_ctx *pctx)
{
	int rv = PAM_AUTH_ERR;

	if (pctx->pli.password != NULL &&
	    pctx->pmi.password != NULL &&
	    strcmp(pctx->pli.password, pctx->pmi.password) == 0) {
		rv = PAM_SUCCESS;
	}

	return rv;
}

static int pam_example_auth(struct pam_example_ctx *pctx)
{
	int rv = PAM_AUTH_ERR;

	rv = _pam_example_auth(pctx);

	wipe_authtok(pctx->pli.password);
	wipe_authtok(pctx->pmi.password);

	return rv;
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

	rv = pam_example_read_password(pamh, PAM_AUTHTOK, "Password: ", NULL,
				       (const void **) &pctx.pli.password);
	if (rv != PAM_SUCCESS) {
		return PAM_AUTHINFO_UNAVAIL;
	}

	rv = pam_example_auth(&pctx);
done:
	pam_example_free(&pctx);
	return rv;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char *argv[])
{
	struct pam_example_ctx pctx;
	int rv;
	char cred[PATH_MAX + CRED_VAR_SZ];

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = snprintf(cred, sizeof(cred),
		      "%s=/tmp/%s",
		      CRED_VAR, pctx.pli.username);
	if (rv <= 0) {
		rv = PAM_BUF_ERR;
		goto done;
	}

	rv = pam_putenv(pamh, cred);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	rv = PAM_SUCCESS;
done:
	pam_example_free(&pctx);
	return rv;
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

	if (pctx.pli.service != NULL &&
	    pctx.pmi.service != NULL &&
	    strcmp(pctx.pli.service, pctx.pmi.service) == 0) {
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

static void pam_example_stamp_destructor(pam_handle_t *pamh,
					 void *data,
					 int error_status)
{
	(void) pamh;		/* unused */
	(void) error_status;	/* unused */

	free(data);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char *argv[])
{
	struct pam_example_ctx pctx;
	const char *old_pass;
	int rv;
	time_t *auth_stamp = NULL;
	const time_t *auth_stamp_out = NULL;

	(void) flags; /* unused */
	(void) argc;  /* unused */
	(void) argv;  /* unused */

	memset(&pctx, 0, sizeof(struct pam_example_ctx));

	rv = pam_example_get(pamh, &pctx);
	if (rv != PAM_SUCCESS) {
		goto done;
	}

	if (flags & PAM_PRELIM_CHECK) {
		rv = pam_example_read_password(
					pamh, PAM_OLDAUTHTOK,
					"Old password: ", NULL,
					(const void **) &pctx.pli.password);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}

		auth_stamp = malloc(sizeof(time_t));
		if (auth_stamp == NULL) {
			rv = PAM_BUF_ERR;
			goto done;
		}
		*auth_stamp = time(NULL);

		rv = pam_set_data(pamh, PAM_EXAMPLE_AUTH_DATA,
				auth_stamp, pam_example_stamp_destructor);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		rv = pam_example_auth(&pctx);
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		rv = pam_get_item(pamh,
				  PAM_OLDAUTHTOK,
				  (const void **) &old_pass);
		if (rv != PAM_SUCCESS || old_pass == NULL) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}


		rv = pam_get_data(pamh, PAM_EXAMPLE_AUTH_DATA,
				  (const void **) &auth_stamp_out);
		if (rv != PAM_SUCCESS) {
			goto done;
		}

		rv = pam_example_read_password(pamh, PAM_AUTHTOK,
					"New Password :",
					"Verify New Password :",
					(const void **) &pctx.pli.password);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto done;
		}

		rv = pam_example_lib_items_put(&pctx.pli);
	} else {
		rv = PAM_SYSTEM_ERR;
	}

done:
	pam_example_free(&pctx);
	return rv;
}
