/*
    Plymouth-based, PAM conversation function
    Copyright (C) 2024-2  Mark A. Williams, Jr.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef __PAMPLY_H
#define __PAMPLY_H

#include <plymouth-1/ply/ply-utils.h>
#include <plymouth-1/ply-boot-client/ply-boot-protocol.h>

#include <security/pam_appl.h>
#include <security/pam_client.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* include some useful macros */

#include <security/_pam_macros.h>

/* functions defined in pam_ply.* libraries */

extern int ply_conv(int num_msg, const struct pam_message **msgm,
		    struct pam_response **response, void *appdata_ptr);

/*
 * Communication helper functions
 */

/* create an endpoint for communication (with plymouthd) */
extern int pam_ply_socket();

#ifdef __cplusplus
}
#endif /* def __cplusplus */

#endif /* ndef __PAMPLY_H */
