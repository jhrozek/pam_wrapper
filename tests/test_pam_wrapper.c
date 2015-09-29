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
#include <security/pam_appl.h>
#include <security/pam_ext.h>

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

static void setup_passdb(void)
{
	int rv;
	const char *db;
	FILE *fp = NULL;
	char passdb_path[PATH_MAX];

	db = getcwd(passdb_path, PATH_MAX);
	assert_non_null(db);
	assert_true(strlen(passdb_path) + sizeof("/passdb") < PATH_MAX);
	db = strncat(passdb_path, "/passdb", sizeof("/passdb"));

	rv = setenv("PWRAP_PASSDB", passdb_path, 1);
	assert_int_equal(rv, 0);

	fp = fopen(db, "w");
	assert_non_null(fp);

	fprintf(fp, "testuser\tsecret\tpwrap_pam\n");
	fprintf(fp, "testuser2\tsecret\tpwrap_wrong_svc");

	fflush(fp);
	fclose(fp);
}

static void teardown_passdb(void)
{
	const char *db;

	db = getenv("PWRAP_PASSDB");
	assert_non_null(db);
	unlink(db);
}

static int setup_ctx_only(void **state)
{
	struct pwrap_test_ctx *test_ctx;

	setup_passdb();

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

	teardown_passdb();

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_end(test_ctx->ph, PAM_SUCCESS);
	assert_int_equal(rv, PAM_SUCCESS);

	return teardown_simple(state);
}

static void test_pam_authenticate(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	const char *testuser_authtoks[] = {
		"secret",
		NULL,
	};
	struct pwrap_conv_data testuser_auth_conv_data = {
		.authtoks = testuser_authtoks,
		.authtok_index = 0,
	};

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) &testuser_auth_conv_data;
	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_authenticate(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);
}

static void test_pam_authenticate_err(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	const char *testuser_authtoks[] = {
		"wrong_password",
		NULL,
	};
	struct pwrap_conv_data testuser_auth_err_conv_data = {
		.authtoks = testuser_authtoks,
		.authtok_index = 0,
	};


	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) &testuser_auth_err_conv_data;
	rv = pam_start("pwrap_pam", "testuser",
			&test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_authenticate(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_AUTH_ERR);
}

static void test_pam_acct(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_acct_mgmt(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);
}

static void test_pam_acct_err(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) "secret";
	rv = pam_start("pwrap_pam", "testuser2",
			&test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_acct_mgmt(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_PERM_DENIED);
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

static void test_pam_session(void **state)
{
	int rv;
	const char *v;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	v = pam_getenv(test_ctx->ph, "HOMEDIR");
	assert_null(v);

	rv = pam_open_session(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);

	v = pam_getenv(test_ctx->ph, "HOMEDIR");
	assert_non_null(v);
	assert_string_equal(v, "/home/testuser");
}

static void test_pam_chauthtok(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	const char *testuser_new_authtoks[] = {
		"secret",
		"new_secret",
		"new_secret",
		NULL,
	};
	struct pwrap_conv_data testuser_chpass_conv_data = {
		.authtoks = testuser_new_authtoks,
		.authtok_index = 0,
	};

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) &testuser_chpass_conv_data;
	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_chauthtok(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);

	testuser_chpass_conv_data.authtok_index = 1;
	rv = pam_authenticate(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);
}

static void test_pam_chauthtok_prelim_failed(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	const char *testuser_new_authtoks[] = {
		"wrong_secret",
		"new_secret",
		"new_secret",
		NULL,
	};
	struct pwrap_conv_data testuser_chpass_conv_data = {
		.authtoks = testuser_new_authtoks,
		.authtok_index = 0,
	};

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) &testuser_chpass_conv_data;
	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_chauthtok(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_AUTH_ERR);
}

static void test_pam_setcred(void **state)
{
	int rv;
	const char *v;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	v = pam_getenv(test_ctx->ph, "CRED");
	assert_null(v);

	rv = pam_setcred(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);

	v = pam_getenv(test_ctx->ph, "CRED");
	assert_non_null(v);
	assert_string_equal(v, "/tmp/testuser");
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

int main(void) {
	int rc;

	const struct CMUnitTest init_tests[] = {
		cmocka_unit_test_setup_teardown(test_pam_start,
						setup_noconv,
						teardown_simple),
		cmocka_unit_test_setup_teardown(test_pam_authenticate,
						setup_ctx_only,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_authenticate_err,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_acct,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_acct_err,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_env_functions,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_session,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_chauthtok,
						setup_ctx_only,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_chauthtok_prelim_failed,
						setup_ctx_only,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_setcred,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_item_functions,
						setup_noconv,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_prompt,
						setup_ctx_only,
						teardown),
	};

	rc = cmocka_run_group_tests(init_tests, NULL, NULL);

	return rc;
}

