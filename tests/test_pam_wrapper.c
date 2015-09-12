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

	*state = test_ctx;
	return 0;
}

static int teardown(void **state)
{
	return teardown_simple(state);
}

static void test_pam_authenticate(void **state)
{
	int rv;
	struct pwrap_test_ctx *test_ctx;

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) "secret";
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

	test_ctx = (struct pwrap_test_ctx *) *state;

	test_ctx->conv.appdata_ptr = (void *) "wrong_password";
	rv = pam_start("pwrap_pam", "testuser",
			&test_ctx->conv, &test_ctx->ph);
	assert_int_equal(rv, PAM_SUCCESS);

	rv = pam_authenticate(test_ctx->ph, 0);
	assert_int_equal(rv, PAM_AUTH_ERR);
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
						setup,
						teardown),
	};

	rc = cmocka_run_group_tests(init_tests, NULL, NULL);

	return rc;
}

