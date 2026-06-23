/*
    Plymouth-based, PAM conversation function
    Copyright (C) 2024-26  Mark A. Williams, Jr.

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

#ifdef PAM_DEBUG
# include <err.h>
#endif
#include <errno.h>
#include <malloc.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <security/pam_appl.h>
#include <security/pam_ply.h>


static ssize_t conv_send(const int sockfd,
                          const struct pam_message *const msg) {
    errno = EINVAL;

    if (msg && msg->msg) do {
        const char *s;

        switch (msg->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            s = PLY_BOOT_PROTOCOL_REQUEST_TYPE_PASSWORD;
            break;

        case PAM_PROMPT_ECHO_ON:
            s = PLY_BOOT_PROTOCOL_REQUEST_TYPE_QUESTION;
            break;

        case PAM_ERROR_MSG:
            s = PLY_BOOT_PROTOCOL_REQUEST_TYPE_ERROR;
            break;

        case PAM_TEXT_INFO:
            s = PLY_BOOT_PROTOCOL_REQUEST_TYPE_SHOW_MESSAGE;
            break;

        case PAM_BINARY_PROMPT:
            if (msg->msg[0]) {
                ssize_t ret, len;

                switch (msg->msg[1]) {
                case '\0':
                    ret = 0;
                    len = 1;
                    break;
                case '\2':
                    if ((ret = 2[(const unsigned char *)msg->msg])) {
                        len = ret + 2;
                        break;
                    }
                default:
                    continue;
                }

                if (send(sockfd, msg->msg, len, MSG_MORE) == len &&
                    send(sockfd, "", 1, 0) == 1) {
                    return ret;
                }
            }
        default:
            continue;
        }

        if (send(sockfd, s, 1, MSG_MORE) == 1) {
            const size_t len = strnlen(msg->msg, UINT8_MAX - 1);
            const unsigned char dat[] = { '\2', len + 1 };

            if (send(sockfd, dat, sizeof dat, MSG_MORE) == sizeof dat &&
                send(sockfd, msg->msg, len, MSG_MORE) == (ssize_t)len &&
                send(sockfd, "", 1, 0) == 1) {
                    return dat[1];
            }
        }
    } while(0);

#ifdef PAM_DEBUG
    warn("conv_send()");
#endif
    return -1;
}

static ssize_t conv_recv(const int sockfd, struct pam_response *const resp) {
    union {
        char ch;
        void *p;
    } res;

    resp->resp_retcode = PAM_CONV_ERR;

    if (recv(sockfd, &res.ch, 1, MSG_WAITALL) == 1) {
        ssize_t ret = 0;

        union {
            int i;
            uint32_t u32;
            size_t n;
        } len = { 0 };

        while (PLY_BOOT_PROTOCOL_RESPONSE_TYPE_ANSWER
               PLY_BOOT_PROTOCOL_RESPONSE_TYPE_MULTIPLE_ANSWERS
               PLY_BOOT_PROTOCOL_RESPONSE_TYPE_ACK
               PLY_BOOT_PROTOCOL_RESPONSE_TYPE_NAK
               PLY_BOOT_PROTOCOL_RESPONSE_TYPE_NO_ANSWER[len.i] != res.ch) {
            if (++len.i == 5) {
                errno = EINVAL;
                goto done;
            }
        }

        switch (len.i) {
        case 0:
        case 1:
            if (recv(sockfd, &len.u32, sizeof len.u32, MSG_WAITALL) == sizeof len.u32) {
                if ((res.p = malloc((len.n = ret = len.u32) + 1))) {
                    mlock(res.p, len.n);
                    if (recv(sockfd, res.p, len.n, MSG_WAITALL) >= ret) {
                        break;
                    }
                    munlock(res.p, len.n);
                    free(res.p);
                } else {
                    resp->resp_retcode = PAM_BUF_ERR;
                }
            }
            goto done;

        case 2:
            res.p = resp;
            break;

        default:
            res.p = NULL;
            break;
        }

        resp->resp = res.p;
        resp->resp_retcode = PAM_SUCCESS;
        return ret;
    }

done:
#ifdef PAM_DEBUG
    warn("conv_recv()");
#endif
    return -1;
}

int ply_conv(const int num_msg, const struct pam_message **const msgv,
             struct pam_response **const prespv, void *appdata_ptr) {
    int ret = PAM_SUCCESS;

    mallopt(M_PERTURB, '\xFF');
    do {
        struct pam_response *const respv = calloc(num_msg, sizeof *respv);

        if (respv) {
            const int sockfd = appdata_ptr && *(const int *)appdata_ptr >= 0
                               ? *(const int *)appdata_ptr
                               : pam_ply_socket();

            if (sockfd == -1) {
                ret = PAM_CONV_ERR;
            } else {
                for (unsigned i = 0;;) {
                    if ((unsigned)num_msg == i) {
                        if (appdata_ptr && *(const int *)appdata_ptr < 0) {
                            *(int *)appdata_ptr = sockfd;
			}
                        *prespv = respv;
                        break;
                    }

                    struct pam_response *resp = respv + i;

                    if (conv_send(sockfd, msgv[i++]) != -1 &&
                        (conv_recv(sockfd, resp), resp->resp_retcode) != PAM_CONV_ERR) {
                        if (resp->resp_retcode == PAM_BUF_ERR) {
                            ret = PAM_BUF_ERR;
                        }
                        continue;
                    }
                    ret = PAM_CONV_ERR;

                    do {
                        free(resp->resp);
                    } while (resp-- != respv);
                    free(respv);

                    break;
                }

                if ((appdata_ptr && *(const int *)appdata_ptr >= 0) || !close(sockfd)) {
                    break;
                }
            }
        } else {
            ret = PAM_BUF_ERR;
        }

#ifdef PAM_DEBUG
        warn("ply_conv()");
#endif
    } while (0);
    mallopt(M_PERTURB, 0);

    return ret;
}
