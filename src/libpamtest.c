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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "libpamtest.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

static enum pamtest_err run_test_case(pam_handle_t *ph,
				      struct pamtest_case *tc)
{
	switch (tc->pam_operation) {
	case PAMTEST_AUTHENTICATE:
		tc->op_rv = pam_authenticate(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_SETCRED:
		tc->op_rv = pam_setcred(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_ACCOUNT:
		tc->op_rv = pam_acct_mgmt(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_OPEN_SESSION:
		tc->op_rv = pam_open_session(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_CLOSE_SESSION:
		tc->op_rv = pam_close_session(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_CHAUTHTOK:
		tc->op_rv = pam_chauthtok(ph, tc->flags);
		return PAMTEST_ERR_OK;
	case PAMTEST_GETENVLIST:
		tc->case_out.envlist = pam_getenvlist(ph);
		return PAMTEST_ERR_OK;
	case PAMTEST_KEEPHANDLE:
		tc->case_out.ph = ph;
		return PAMTEST_ERR_KEEPHANDLE;
	default:
		return PAMTEST_ERR_OP;
	}

	return PAMTEST_ERR_OP;
}

enum pamtest_err pamtest_ex(const char *service,
			    const char *user,
			    pam_conv_fn conv_fn,
			    void *conv_userdata,
			    struct pamtest_case *test_cases)
{
	int rv;
	pam_handle_t *ph;
	struct pam_conv conv;
	size_t tcindex;
	struct pamtest_case *tc;
	bool call_pam_end = true;

	conv.conv = conv_fn;
	conv.appdata_ptr = conv_userdata;

	if (test_cases == NULL) {
		return PAMTEST_ERR_INTERNAL;
	}

	rv = pam_start(service, user, &conv, &ph);
	if (rv != PAM_SUCCESS) {
		return PAMTEST_ERR_START;
	}

	for (tcindex = 0;
	     test_cases[tcindex].pam_operation != PAMTEST_SENTINEL;
	     tcindex++) {
		tc = &test_cases[tcindex];

		rv = run_test_case(ph, tc);
		if (rv == PAMTEST_ERR_KEEPHANDLE) {
			call_pam_end = false;
			continue;
		} else if (rv != PAMTEST_ERR_OK) {
			return PAMTEST_ERR_INTERNAL;
		}

		if (tc->op_rv != tc->expected_rv) {
			break;
		}
	}

	if (call_pam_end == true) {
		rv = pam_end(ph, tc->op_rv);
		if (rv != PAM_SUCCESS) {
			return PAMTEST_ERR_END;
		}
	}

	if (test_cases[tcindex].pam_operation != PAMTEST_SENTINEL) {
		return PAMTEST_ERR_CASE;
	}

	return PAMTEST_ERR_OK;
}

void pamtest_free_env(char **envlist)
{
	if (envlist == NULL) {
		return;
	}

	for (size_t i = 0; envlist[i] != NULL; i++) {
		free(envlist[i]);
	}
	free(envlist);
}

const struct pamtest_case *pamtest_failed_case(struct pamtest_case *test_cases)
{
	size_t tcindex;

	for (tcindex = 0;
	     test_cases[tcindex].pam_operation != PAMTEST_SENTINEL;
	     tcindex++) {
		const struct pamtest_case *tc = &test_cases[tcindex];

		if (tc->expected_rv != tc->op_rv) {
			return tc;
		}
	}

	/* Nothing failed */
	return NULL;
}

struct pamtest_conv_ctx {
	struct pamtest_conv_data *data;

	size_t echo_off_idx;
	size_t echo_on_idx;
	size_t err_idx;
	size_t info_idx;
};

static int add_to_reply(struct pam_response *reply, const char *str)
{
	size_t len;

	len = strlen(str) + 1;

	reply->resp = calloc(len, sizeof(char));
	if (reply->resp == NULL) {
		return PAM_BUF_ERR;
	}

	memcpy(reply->resp, str, len);
	return PAM_SUCCESS;
}

static int pamtest_simple_conv(int num_msg,
			       const struct pam_message **msgm,
			       struct pam_response **response,
			       void *appdata_ptr)
{
	int i;
	int ret;
	struct pam_response *reply;
	const char *prompt;
	struct pamtest_conv_ctx *cctx = \
				    (struct pamtest_conv_ctx *) appdata_ptr;

	if (cctx == NULL) {
		return PAM_CONV_ERR;
	}

	reply = (struct pam_response *) calloc(num_msg,
					       sizeof(struct pam_response));
	if (reply == NULL) {
		return PAM_CONV_ERR;
	}

	for (i=0; i < num_msg; i++) {
		switch (msgm[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			prompt = (const char *) \
				   cctx->data->in_echo_off[cctx->echo_off_idx];
			if (prompt == NULL) {
				return PAM_CONV_ERR;
			}

			ret = add_to_reply(&reply[i], prompt);
			if (ret != PAM_SUCCESS) {
				/* FIXME - free data? */
				return ret;
			}

			cctx->echo_off_idx++;
			break;
		case PAM_PROMPT_ECHO_ON:
			prompt = (const char *) \
				   cctx->data->in_echo_on[cctx->echo_on_idx];
			if (prompt == NULL) {
				return PAM_CONV_ERR;
			}

			ret = add_to_reply(&reply[i], prompt);
			if (ret != PAM_SUCCESS) {
				/* FIXME - free data? */
				return ret;
			}

			cctx->echo_on_idx++;
			break;
		case PAM_ERROR_MSG:
			if (cctx->data->out_err != NULL) {
				memcpy(cctx->data->out_err[cctx->err_idx],
				       msgm[i]->msg,
				       MIN(strlen(msgm[i]->msg),
					   PAM_MAX_MSG_SIZE));
				cctx->err_idx++;
			}
			break;
		case PAM_TEXT_INFO:
			if (cctx->data->out_info != NULL) {
				memcpy(cctx->data->out_info[cctx->info_idx],
				       msgm[i]->msg,
				       MIN(strlen(msgm[i]->msg),
					   PAM_MAX_MSG_SIZE));
				cctx->info_idx++;
			}
			break;
		default:
			continue;
		}
	}

	if (response) {
		*response = reply;
	}
	return PAM_SUCCESS;
}

enum pamtest_err pamtest(const char *service,
			 const char *user,
			 struct pamtest_conv_data *conv_data,
			 struct pamtest_case *test_cases)
{
	struct pamtest_conv_ctx cctx;

	cctx.data = conv_data;
	cctx.echo_on_idx = 0;
	cctx.echo_off_idx = 0;
	cctx.err_idx = 0;
	cctx.info_idx = 0;

	return pamtest_ex(service, user,
			  pamtest_simple_conv, &cctx, 
			  test_cases);
}
