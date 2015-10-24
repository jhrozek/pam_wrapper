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

#ifndef __LIBPAMTEST_H_
#define __LIBPAMTEST_H_

#include <stdint.h>
#include <security/pam_appl.h>

/* operations */
enum pamtest_ops {
	/* These operations correspond to libpam ops */
	PAMTEST_AUTHENTICATE,
	PAMTEST_SETCRED,
	PAMTEST_ACCOUNT,
	PAMTEST_OPEN_SESSION,
	PAMTEST_CLOSE_SESSION,
	PAMTEST_CHAUTHTOK,

	/* These operation affect test output */
	PAMTEST_GETENVLIST,	/* Call pam_getenvlist. */
	PAMTEST_KEEPHANDLE,	/* Don't call pam_end() but return handle */

	/* The two below can't be set by API user, but are useful if pam_start()
	 * or pam_end() fails and the API user wants to find out what happened
	 * with pamtest_failed_case()
	 */
	PAMTEST_START,
	PAMTEST_END,

	/* Boundary.. */
	PAMTEST_SENTINEL,
};

struct pamtest_case {
	enum pamtest_ops pam_operation;	  /* The pam operation to run */
	int expected_rv;		  /* What we expect the op to return */
	int flags;			  /* Extra flags to pass to the op */

	int op_rv;			  /* What the op really returns */

	union {
		char **envlist;		/* output of PAMTEST_ENVLIST */
		pam_handle_t *ph;	/* output of PAMTEST_KEEPHANDLE */
	} case_out;		/* depends on pam_operation, mostly unused */
};

#define PAMTEST_CASE_INIT 0, 0, { .envlist = NULL }
#define PAMTEST_CASE_SENTINEL PAMTEST_SENTINEL, 0, PAMTEST_CASE_INIT

enum pamtest_err {
	PAMTEST_ERR_OK,		/* Testcases returns correspond with input */
	PAMTEST_ERR_START,	/* pam_start() failed */
	PAMTEST_ERR_CASE,	/* A testcase failed. Use pamtest_failed_case */
	PAMTEST_ERR_OP,		/* Could not run a test case */
	PAMTEST_ERR_END,	/* pam_end failed */
	PAMTEST_ERR_KEEPHANDLE, /* Handled internally */
	PAMTEST_ERR_INTERNAL,   /* Internal error - bad input or similar */
};

typedef int (*pam_conv_fn)(int num_msg,
			   const struct pam_message **msg,
			   struct pam_response **resp,
			   void *appdata_ptr);

enum pamtest_err pamtest_ex(const char *service,
			    const char *user,
			    pam_conv_fn conv_fn,
			    void *conv_userdata,
			    struct pamtest_case *test_cases);

void pamtest_free_env(char **envlist);

const struct pamtest_case *pamtest_failed_case(struct pamtest_case *test_cases);

struct pamtest_conv_data {
	const char **in_echo_off;
	const char **in_echo_on;

	char **out_err;
	char **out_info;
};

enum pamtest_err pamtest(const char *service,
			 const char *user,
			 struct pamtest_conv_data *conv_data,
			 struct pamtest_case *test_cases);

#endif /* __LIBPAMTEST_H_ */
