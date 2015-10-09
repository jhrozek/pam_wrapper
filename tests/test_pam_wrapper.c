#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

#include "libpamtest.h"

struct pwrap_test_ctx {
	struct pam_conv conv;
	pam_handle_t *ph;
};

struct pwrap_conv_data {
	const char **authtoks;
	size_t authtok_index;
};

static int pwrap_conv(int num_msg, const struct pam_message **msgm,
		      struct pam_response **response,
		      void *appdata_ptr)
{
	int i;
	struct pam_response *reply;
	const char *password;
	size_t pwlen;
	struct pwrap_conv_data *cdata = (struct pwrap_conv_data *) appdata_ptr;

	if (cdata == NULL) {
		return PAM_CONV_ERR;
	}

	reply = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		return PAM_CONV_ERR;
	}

	for (i=0; i < num_msg; i++) {
		switch (msgm[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			password = (const char *) cdata->authtoks[cdata->authtok_index];
			if (password == NULL) {
				return PAM_CONV_ERR;
			}

			pwlen = strlen(password) + 1;

			cdata->authtok_index++;

			reply[i].resp = calloc(pwlen, sizeof(char));
			if (reply[i].resp == NULL) {
				free(reply);
				return PAM_CONV_ERR;
			}
			memcpy(reply[i].resp, password, pwlen);
			break;
		default:
			continue;
		}
	}

	*response = reply;
	return PAM_SUCCESS;
}

static int setup_passdb(void **state)
{
	int rv;
	const char *db;
	FILE *fp = NULL;
	char passdb_path[PATH_MAX];

	(void) state;	/* unused */

	db = getcwd(passdb_path, PATH_MAX);
	assert_non_null(db);
	assert_true(strlen(passdb_path) + sizeof("/passdb") < PATH_MAX);
	db = strncat(passdb_path, "/passdb", sizeof("/passdb"));

	rv = setenv("PAM_MATRIX_PASSWD", passdb_path, 1);
	assert_int_equal(rv, 0);

	fp = fopen(db, "w");
	assert_non_null(fp);

	fprintf(fp, "testuser:secret:pwrap_pam\n");
	fprintf(fp, "testuser2:secret:pwrap_wrong_svc");

	fflush(fp);
	fclose(fp);

	return 0;
}

static int teardown_passdb(void **state)
{
	const char *db;

	(void) state;	/* unused */

	db = getenv("PAM_MATRIX_PASSWD");
	assert_non_null(db);
	unlink(db);

	/* Don't pollute environment for other tests */
	unsetenv("PAM_MATRIX_PASSWD");

	return 0;
}

static int setup_ctx_only(void **state)
{
	struct pwrap_test_ctx *test_ctx;

	setup_passdb(NULL);

	test_ctx = malloc(sizeof(struct pwrap_test_ctx));
	assert_non_null(test_ctx);

	test_ctx->conv.conv = pwrap_conv;

	*state = test_ctx;
	return 0;
}

static int setup_noconv(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;

	setup_ctx_only(state);
	test_ctx = *state;

	/* We'll get an error if the test module talks to us */
	test_ctx->conv.appdata_ptr = NULL;

	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	*state = test_ctx;
	return 0;
}

static int teardown_simple(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	test_ctx = (struct pwrap_test_ctx *) *state;

	free(test_ctx);
	return 0;
}

static void test_pam_start(void **state)
{
	int rv;
	pam_handle_t *ph;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;
	test_ctx->conv.appdata_ptr = (void *) "testpassword";

	rv = pam_start("pwrap_pam", "testuser", &test_ctx->conv, &ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_end(ph, PAM_SUCCESS);
	assert_int_equal(rv, PAM_SUCCESS);
}

static int teardown(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;

	teardown_passdb(NULL);

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_end(test_ctx->ph, PAM_SUCCESS);
	assert_int_equal(rv, PAM_SUCCESS);

	return teardown_simple(state);
}

static void test_pam_authenticate(void **state)
{
	enum pamtest_err perr;
	const char *testuser_authtoks[] = {
		"secret",
		NULL,
	};
	struct pamtest_case tests[] = {
		{ PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", testuser_authtoks, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_authenticate_err(void **state)
{
	enum pamtest_err perr;
	const char *testuser_authtoks[] = {
		"wrong_password",
		NULL,
	};
	struct pamtest_case tests[] = {
		{ PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", testuser_authtoks, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_acct(void **state)
{
	enum pamtest_err perr;
	struct pamtest_case tests[] = {
		{ PAMTEST_ACCOUNT, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", NULL, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_acct_err(void **state)
{
	enum pamtest_err perr;
	struct pamtest_case tests[] = {
		{ PAMTEST_ACCOUNT, PAM_PERM_DENIED, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser2", NULL, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static inline void free_vlist(char **vlist)
{
	free(vlist[0]);
	free(vlist[1]);
	free(vlist);
}

static void test_pam_env_functions(void **state)
{
	int rv;
	const char *v;
	char **vlist;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_putenv(test_ctx->ph, "KEY=value");
	assert_int_equal(rv, PAM_SUCCESS);
	rv = pam_putenv(test_ctx->ph, "KEY2=value2");
	assert_int_equal(rv, PAM_SUCCESS);

	v = pam_getenv(test_ctx->ph, "KEY");
	assert_non_null(v);
	assert_string_equal(v, "value");

	v = pam_getenv(test_ctx->ph, "KEY2");
	assert_non_null(v);
	assert_string_equal(v, "value2");

	vlist = pam_getenvlist(test_ctx->ph);
	assert_non_null(vlist);
	assert_non_null(vlist[0]);
	assert_string_equal(vlist[0], "KEY=value");
	assert_non_null(vlist[1]);
	assert_string_equal(vlist[1], "KEY2=value2");
	assert_null(vlist[2]);
	free_vlist(vlist);

	rv = pam_putenv(test_ctx->ph, "KEY2=");
	assert_int_equal(rv, PAM_SUCCESS);

	vlist = pam_getenvlist(test_ctx->ph);
	assert_non_null(vlist);
	assert_non_null(vlist[0]);
	assert_string_equal(vlist[0], "KEY=value");
	assert_non_null(vlist[1]);
	assert_string_equal(vlist[1], "KEY2=");
	assert_null(vlist[2]);
	free_vlist(vlist);

	rv = pam_putenv(test_ctx->ph, "KEY2");
	assert_int_equal(rv, PAM_SUCCESS);

	vlist = pam_getenvlist(test_ctx->ph);
	assert_non_null(vlist);
	assert_non_null(vlist[0]);
	assert_string_equal(vlist[0], "KEY=value");
	assert_null(vlist[1]);
	free_vlist(vlist);
}

static const char *string_in_list(char **list, const char *key)
{
	char key_eq[strlen(key)+1+1]; /* trailing NULL and '=' */

	if (list == NULL || key == NULL) {
		return NULL;
	}

	snprintf(key_eq, sizeof(key_eq), "%s=", key);
	for (size_t i = 0; list[i] != NULL; i++) {
		if (strncmp(list[i], key_eq, sizeof(key_eq)-1) == 0) {
			return list[i] + sizeof(key_eq)-1;
		}
	}

	return NULL;
}

static void test_pam_session(void **state)
{
	enum pamtest_err perr;
	const char *v;
	struct pamtest_case tests[] = {
		{ PAMTEST_OPEN_SESSION, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_GETENVLIST, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_CLOSE_SESSION, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_GETENVLIST, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", NULL, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);

	v = string_in_list(tests[1].case_out.envlist, "HOMEDIR");
	assert_non_null(v);
	assert_string_equal(v, "/home/testuser");

	pamtest_free_env(tests[1].case_out.envlist);

	/* environment is cleared after session close */
	assert_non_null(tests[3].case_out.envlist);
	assert_null(tests[3].case_out.envlist[0]);
	pamtest_free_env(tests[3].case_out.envlist);
}

static void test_pam_chauthtok(void **state)
{
	enum pamtest_err perr;
	const char *testuser_new_authtoks[] = {
		"secret",	    /* old password */
		"new_secret",	    /* new password */
		"new_secret",	    /* verify new password */
		"new_secret",	    /* login with the new password */
		NULL,
	};
	struct pamtest_case tests[] = {
		{ PAMTEST_CHAUTHTOK, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", testuser_new_authtoks, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_chauthtok_prelim_failed(void **state)
{
	enum pamtest_err perr;
	const char *testuser_new_authtoks[] = {
		"wrong_secret",	    /* old password */
		"new_secret",	    /* new password */
		"new_secret",	    /* verify new password */
		NULL,
	};
	struct pamtest_case tests[] = {
		{ PAMTEST_CHAUTHTOK, PAM_AUTH_ERR, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", testuser_new_authtoks, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_setcred(void **state)
{
	enum pamtest_err perr;
	const char *v;
	struct pamtest_case tests[] = {
		{ PAMTEST_GETENVLIST, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SETCRED, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_GETENVLIST, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam", "testuser", NULL, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);

	/* environment is clean before setcred */
	assert_non_null(tests[0].case_out.envlist);
	assert_null(tests[0].case_out.envlist[0]);
	pamtest_free_env(tests[0].case_out.envlist);

	/* and has an item after setcred */
	v = string_in_list(tests[2].case_out.envlist, "CRED");
	assert_non_null(v);
	assert_string_equal(v, "/tmp/testuser");
	pamtest_free_env(tests[2].case_out.envlist);
}

static void test_pam_item_functions(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	const char *item;
	int rv;

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_get_item(test_ctx->ph, PAM_USER, (const void **) &item);
	assert_int_equal(rv, PAM_SUCCESS);
	assert_string_equal(item, "testuser");

	rv = pam_set_item(test_ctx->ph, PAM_USER_PROMPT, "test_login");
	assert_int_equal(rv, PAM_SUCCESS);
	assert_string_equal(item, "testuser");

	rv = pam_get_item(test_ctx->ph, PAM_USER_PROMPT, (const void **) &item);
	assert_int_equal(rv, PAM_SUCCESS);
	assert_string_equal(item, "test_login");

	rv = pam_get_item(test_ctx->ph, PAM_AUTHTOK, (const void **) &item);
	assert_int_equal(rv, PAM_BAD_ITEM);

	rv = pam_set_item(test_ctx->ph, PAM_AUTHTOK, "mysecret");
	assert_int_equal(rv, PAM_BAD_ITEM);
}

static int add_to_reply(struct pam_response *res,
			const char *s1,
			const char *s2)
{
	size_t res_len;
	int rv;

	res_len = strlen(s1) + strlen(s2) + 1;

	res->resp = calloc(res_len, sizeof(char));
	if (res->resp == NULL) {
		return ENOMEM;
	}

	rv = snprintf(res->resp, res_len, "%s%s", s1, s2);
	if (rv < 0) {
		return EIO;
	}

	return 0;
}

static int pwrap_echo_conv(int num_msg,
			   const struct pam_message **msgm,
			   struct pam_response **response,
			   void *appdata_ptr)
{
	int i;
	struct pam_response *reply;
	int *resp_array = appdata_ptr;

	reply = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		return PAM_CONV_ERR;
	}

	for (i=0; i < num_msg; i++) {
		switch (msgm[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			add_to_reply(&reply[i], "echo off: ", msgm[i]->msg);
			break;
		case PAM_PROMPT_ECHO_ON:
			add_to_reply(&reply[i], "echo on: ", msgm[i]->msg);
			break;
		case PAM_TEXT_INFO:
			resp_array[0] = 1;
			break;
		case PAM_ERROR_MSG:
			resp_array[1] = 1;
			break;
		default:
			break;
		}
	}

	*response = reply;
	return PAM_SUCCESS;
}

static void test_pam_prompt(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;
	char *response;
	int resp_array[2];

	test_ctx = (struct pwrap_test_ctx *) *state;

	memset(resp_array, 0, sizeof(resp_array));

	test_ctx->conv.conv = pwrap_echo_conv;
	test_ctx->conv.appdata_ptr = resp_array;

	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_prompt(test_ctx->ph, PAM_PROMPT_ECHO_OFF, &response, "no echo");
	assert_int_equal(rv, PAM_SUCCESS);
	assert_string_equal(response, "echo off: no echo");
	free(response);

	rv = pam_prompt(test_ctx->ph, PAM_PROMPT_ECHO_ON, &response, "echo");
	assert_int_equal(rv, PAM_SUCCESS);
	assert_string_equal(response, "echo on: echo");
	free(response);

	assert_int_equal(resp_array[0], 0);
	pam_info(test_ctx->ph, "info");
	assert_int_equal(resp_array[0], 1);

	assert_int_equal(resp_array[1], 0);
	pam_error(test_ctx->ph, "error");
	assert_int_equal(resp_array[1], 1);
}

static void test_pam_strerror(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	const char *s = NULL;

	test_ctx = (struct pwrap_test_ctx *) *state;

	s = pam_strerror(test_ctx->ph, PAM_AUTH_ERR);
	assert_non_null(s);
}

static void test_pam_authenticate_db_opt(void **state)
{
	enum pamtest_err perr;
	const char *testuser_authtoks[] = {
		"secret_ro",
		NULL,
	};
	struct pamtest_case tests[] = {
		{ PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
		{ PAMTEST_SENTINEL, 0, 0, 0 },
	};

	(void) state;	/* unused */

	perr = pamtest("pwrap_pam_opt", "testuser_ro",
		       testuser_authtoks, tests);
	assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_vsyslog(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;

	test_ctx = (struct pwrap_test_ctx *) *state;
	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	pam_syslog(test_ctx->ph, LOG_INFO, "This is pam_wrapper test\n");
}

int main(void) {
	int rc;

	const struct CMUnitTest init_tests[] = {
		cmocka_unit_test_setup_teardown(test_pam_start,
						setup_noconv,
						teardown_simple),
		cmocka_unit_test_setup_teardown(test_pam_authenticate,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_authenticate_err,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_acct,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_acct_err,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_env_functions,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_session,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_chauthtok,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_chauthtok_prelim_failed,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_setcred,
						setup_passdb,
						teardown_passdb),
		cmocka_unit_test_setup_teardown(test_pam_item_functions,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_prompt,
						setup_ctx_only,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_strerror,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_authenticate_db_opt,
						setup_ctx_only,
						teardown_simple),
		cmocka_unit_test_setup_teardown(test_pam_vsyslog,
						setup_noconv,
						teardown),
	};

	rc = cmocka_run_group_tests(init_tests, NULL, NULL);

	return rc;
}

