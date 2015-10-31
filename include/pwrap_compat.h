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

/* OpenPAM doesn't define PAM_BAD_ITEM */
#ifndef PAM_BAD_ITEM
#define PAM_BAD_ITEM	PAM_SYSTEM_ERR
#endif /* PAM_BAD_ITEM */

/* BSD doesn't have FTW_* flags */
#ifndef FTW_ACTIONRETVAL
#define PWR_FTW_CONTINUE        0
#define PWR_FTW_SKIP_SUBTREE    0
#define PWR_FTW_STOP            1
#define PWR_NFTW_FLAGS          0
#else   /* Linux uses the flags.. */
#define PWR_FTW_CONTINUE        FTW_CONTINUE
#define PWR_FTW_SKIP_SUBTREE    FTW_SKIP_SUBTREE
#define PWR_FTW_STOP            FTW_STOP
#define PWR_NFTW_FLAGS          FTW_ACTIONRETVAL
#endif

#ifdef HAVE_OPENPAM
#define PAMH_QUALIFIER  const
#endif
