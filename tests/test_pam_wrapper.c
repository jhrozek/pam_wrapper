#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

struct pwrap_test_ctx {
	struct pam_conv conv;
	pam_handle_t *ph;
};

static int pwrap_conv(int num_msg, const struct pam_message **msgm,
		      struct pam_response **response,
		      void *appdata_ptr)
{
	int i;
	struct pam_response *reply;
	const char *password;
	size_t pwlen;

	reply = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL) {
		return PAM_CONV_ERR;

	}

	for (i=0; i < num_msg; i++) {
		switch (msgm[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			password = (const char *) appdata_ptr;
			pwlen = strlen(password) + 1;

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

static int setup_simple(void **state)
{
	struct pwrap_test_ctx *test_ctx;

	test_ctx =  malloc(sizeof(struct pwrap_test_ctx));
	assert_non_null(test_ctx);

	test_ctx->conv.conv = pwrap_conv;

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

static int setup(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;

	rv = setup_simple((void **) &test_ctx);
	if (rv != 0) {
		return rv;
	}

	test_ctx->conv.appdata_ptr = (void *) "secret";
	rv = pam_start("pwrap_pam", "testuser",
		       &test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	struct pwrap_test_ctx *test_ctx;
	int rv;

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_end(test_ctx->ph, PAM_SUCCESS);
	assert_int_equal(rv, PAM_SUCCESS);

	return teardown_simple(state);
}

static void test_pam_authenticate(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	rv = pam_authenticate(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_SUCCESS);
}

static void test_pam_authenticate_err(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) "wrong_password";
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

int main(void) {
	int rc;

	const struct CMUnitTest init_tests[] = {
		cmocka_unit_test_setup_teardown(test_pam_start,
						setup_simple,
						teardown_simple),
		cmocka_unit_test_setup_teardown(test_pam_authenticate,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_authenticate_err,
						setup_simple,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_acct,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_acct_err,
						setup_simple,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_env_functions,
						setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_pam_session,
						setup,
						teardown),
	};

	rc = cmocka_run_group_tests(init_tests, NULL, NULL);

	return rc;
}

