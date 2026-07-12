/*
    Generic conversation function
    Copyright (C) XXXX-2026  Andrew Morgan <morgan@linux.kernel.org>
    Copyright (C) 2022-2026  Mark A. Williams, Jr.

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

#include "config.h"

#ifdef USE_PLYMOUTH
# include <fcntl.h>
# include <limits.h>
# include <linux/sched.h>
# include <linux/vt.h>
# include <paths.h>
# include <poll.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <sys/syscall.h>
# include <sys/sysmacros.h>
# include <sys/wait.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#ifdef USE_PLYMOUTH
# include <security/pam_ply.h>
#endif

#include "pam_inline.h"
#include "pam_i18n.h"

#define INPUTSIZE PAM_MISC_CONV_BUFSIZE      /* maximum length of input+1 */
#define CONV_ECHO_ON  1                            /* types of echo state */
#define CONV_ECHO_OFF 0

#ifdef USE_PLYMOUTH
# ifndef _PATH_PLYHOME
#  define _PATH_PLYHOME (_PATH_VARRUN "plymouth")
# endif
#endif

/*
 * external timeout definitions - these can be overridden by the
 * application.
 */

time_t pam_misc_conv_warn_time = 0;                  /* time when we warn */
time_t pam_misc_conv_die_time  = 0;               /* time when we timeout */

const char *pam_misc_conv_warn_line = N_("...Time is running out...\n");
const char *pam_misc_conv_die_line  = N_("...Sorry, your time is up!\n");

int pam_misc_conv_died=0;       /* application can probe this for timeout */

/*
 * These functions are for binary prompt manipulation.
 * The manner in which a binary prompt is processed is application
 * specific, so these function pointers are provided and can be
 * initialized by the application prior to the conversation function
 * being used.
 */

static void pam_misc_conv_delete_binary(void *appdata UNUSED,
					pamc_bp_t *delete_me)
{
    PAM_BP_RENEW(delete_me, 0, 0);
}

int (*pam_binary_handler_fn)(void *appdata, pamc_bp_t *prompt_p) = NULL;
void (*pam_binary_handler_free)(void *appdata, pamc_bp_t *prompt_p)
      = pam_misc_conv_delete_binary;

/* the following code is used to get text input */

static volatile sig_atomic_t expired=0;

/* return to the previous signal handling */
static void reset_alarm(struct sigaction *o_ptr)
{
    (void) alarm(0);                 /* stop alarm clock - if still ticking */
    (void) sigaction(SIGALRM, o_ptr, NULL);
}

/* this is where we intercept the alarm signal */
static void time_is_up(int ignore UNUSED)
{
    expired = 1;
}

/* set the new alarm to hit the time_is_up() function */
static int set_alarm(int delay, struct sigaction *o_ptr)
{
    struct sigaction new_sig;

    sigemptyset(&new_sig.sa_mask);
    new_sig.sa_flags = 0;
    new_sig.sa_handler = time_is_up;
    if ( sigaction(SIGALRM, &new_sig, o_ptr) ) {
	return 1;         /* setting signal failed */
    }
    if ( alarm(delay) ) {
	(void) sigaction(SIGALRM, o_ptr, NULL);
	return 1;         /* failed to set alarm */
    }
    return 0;             /* all seems to have worked */
}

/* return the number of seconds to next alarm. 0 = no delay, -1 = expired */
static int get_delay(void)
{
    time_t now;

    expired = 0;                                        /* reset flag */
    (void) time(&now);

    /* has the quit time passed? */
    if (pam_misc_conv_die_time && now >= pam_misc_conv_die_time) {
	fprintf(stderr,"%s",pam_misc_conv_die_line);

	pam_misc_conv_died = 1;       /* note we do not reset the die_time */
	return -1;                                           /* time is up */
    }

    /* has the warning time passed? */
    if (pam_misc_conv_warn_time && now >= pam_misc_conv_warn_time) {
	fprintf(stderr, "%s", pam_misc_conv_warn_line);
	pam_misc_conv_warn_time = 0;                    /* reset warn_time */

	/* indicate remaining delay - if any */

	return (pam_misc_conv_die_time ? pam_misc_conv_die_time - now:0 );
    }

    /* indicate possible warning delay */

    if (pam_misc_conv_warn_time)
	return (pam_misc_conv_warn_time - now);
    else if (pam_misc_conv_die_time)
	return (pam_misc_conv_die_time - now);
    else
	return 0;
}

/* read a line of input string, giving prompt when appropriate */
static int read_string(int echo, const char *prompt, char **retstr)
{
    struct termios term_before, term_tmp;
    char line[INPUTSIZE];
    struct sigaction old_sig;
    int delay, nc = -1, have_term = 0;
    sigset_t oset, nset;

    D(("called with echo='%s', prompt='%s'.", echo ? "ON":"OFF" , prompt));

    if (isatty(STDIN_FILENO)) {                      /* terminal state */

	/* is a terminal so record settings and flush it */
	if ( tcgetattr(STDIN_FILENO, &term_before) != 0 ) {
	    D(("<error: failed to get terminal settings>"));
	    *retstr = NULL;
	    return -1;
	}
	memcpy(&term_tmp, &term_before, sizeof(term_tmp));
	if (echo)
	    term_tmp.c_lflag |= ICANON | ECHOCTL;
	else
	    term_tmp.c_lflag &= ~(ECHO);
	have_term = 1;

	/*
	 * We make a simple attempt to block TTY signals from suspending
	 * the conversation without giving PAM a chance to clean up.
	 */

	sigemptyset(&nset);
	sigaddset(&nset, SIGTSTP);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);

    } else if (!echo) {
	D(("<warning: cannot turn echo off>"));
    }

    /* set up the signal handling */
    delay = get_delay();

    /* reading the line */
    while (delay >= 0) {
	/* this may, or may not set echo off -- drop pending input */
	if (have_term)
	    (void) tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_tmp);

	fprintf(stderr, "%s", prompt);

	if ( delay > 0 && set_alarm(delay, &old_sig) ) {
	    D(("<failed to set alarm>"));
	    break;
	} else {
	    if (have_term)
		nc = read(STDIN_FILENO, line, INPUTSIZE-1);
	    else                             /* we must read one line only */
		for (nc = 0; nc < INPUTSIZE-1 && (nc?line[nc-1]:0) != '\n';
		     nc++) {
		    int rv;
		    if ((rv=read(STDIN_FILENO, line+nc, 1)) != 1) {
			if (rv < 0) {
			    pam_overwrite_n(line, (unsigned int) nc);
			    nc = rv;
			}
			break;
		    }
		}
	    if (have_term) {
		(void) tcsetattr(STDIN_FILENO, TCSADRAIN, &term_before);
		if (!echo || expired)             /* do we need a newline? */
		    fprintf(stderr, "\n");
	    }
	    if ( delay > 0 ) {
		reset_alarm(&old_sig);
	    }
	    if (expired) {
		delay = get_delay();
	    } else if (nc > 0) {                 /* we got some user input */
		D(("we got some user input"));

		if (line[nc-1] == '\n') {     /* <NUL> terminate */
		    line[--nc] = '\0';
		} else {
		    if (echo) {
			fprintf(stderr, "\n");
		    }
		    line[nc] = '\0';
		}
		*retstr = strdup(line);
		pam_overwrite_array(line);
		if (!*retstr) {
		    D(("no memory for response string"));
		    nc = -1;
		}

		goto cleanexit;                /* return malloc()ed string */

	    } else if (nc == 0) {                                /* Ctrl-D */
		D(("user did not want to type anything"));

		*retstr = NULL;
		if (echo) {
		    fprintf(stderr, "\n");
		}
		goto cleanexit;                /* return malloc()ed "" */
	    } else if (nc == -1) {
		/* Don't loop forever if read() returns -1. */
		D(("error reading input from the user: %m"));
		if (echo) {
		    fprintf(stderr, "\n");
		}
		*retstr = NULL;
		goto cleanexit;                /* return NULL */
	    }
	}
    }

    /* getting here implies that the timer expired */

    D(("the timer appears to have expired"));

    *retstr = NULL;
    pam_overwrite_array(line);

 cleanexit:

    if (have_term) {
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_before);
    }

    return nc;
}

/* end of read_string functions */

/*
 * This conversation function is supposed to be a generic PAM one.
 * Unfortunately, it is _not_ completely compatible with the Solaris PAM
 * codebase.
 *
 * Namely, for msgm's that contain multiple prompts, this function
 * interprets "const struct pam_message **msgm" as equivalent to
 * "const struct pam_message *msgm[]". The Solaris module
 * implementation interprets the **msgm object as a pointer to a
 * pointer to an array of "struct pam_message" objects (that is, a
 * confusing amount of pointer indirection).
 */

int misc_conv(int num_msg, const struct pam_message **msgm,
	      struct pam_response **response, void *appdata_ptr)
{
    int count=0;
    struct pam_response *reply;

    if (num_msg <= 0)
	return PAM_CONV_ERR;

#ifdef USE_PLYMOUTH
    if (getppid() == 1 && (reply = (void *)getenv("XDG_CURRENT_DESKTOP"))) {
        const bool do_retain_splash = strcmp((const void *)reply, "tty");

        char arg2[TTY_NAME_MAX + 6] = "--tty=" _PATH_TTY "7";
        struct stat st[1];

        count = 3;
        reply = NULL;
        ttyname_r(STDIN_FILENO, arg2 + 6, sizeof arg2 - 6);

        do {
            static int killfd = -1;

            struct pam_message msg = {
                .msg_style = PAM_BINARY_PROMPT,
                .msg = PLY_BOOT_PROTOCOL_REQUEST_TYPE_HAS_ACTIVE_VT,
            };

            const struct pam_message *msgs[] = { &msg };
            int sockfd = -1;

            struct ucred cred = { -1, -1, -1 };
            socklen_t n = sizeof cred;

            D(("waiting until VT has been activated."));

            if (fstat(STDIN_FILENO, st) ||
                ioctl(STDIN_FILENO, VT_WAITACTIVE, minor(st->st_rdev))) {
                continue;
            }

            switch (ply_conv(1, msgs, &reply, &sockfd)) {
            default:
                const char *const s = reply->resp;

                free(reply);
                reply = NULL;

                if (s) {
                    break;
                }
                getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &n);

                struct pollfd pfd[] = {
                    {
                        .fd = syscall(SYS_pidfd_open, cred.pid, 0),
                        .events = POLLIN,
                    },
                };

                D(("closing plymouth boot splash."));

                msg.msg = PLY_BOOT_PROTOCOL_REQUEST_TYPE_QUIT "\2\2\1";
                if (ply_conv(1, msgs, &reply, &sockfd) != PAM_SUCCESS) {
                    tgkill(cred.pid, cred.pid, SIGHUP);
                }

                free(reply);
                reply = NULL;

                close(sockfd);
                sockfd = -1;
                n = sizeof cred;

                if (pfd->fd != -1) {
                    while (poll(pfd, 1, -1) == -1 && errno == EINTR) { }
                    close(pfd->fd);
                } else if (errno != ESRCH) {
                    usleep(250000);
                }
                [[fallthrough]];

            case PAM_CONV_ERR:
                siginfo_t si = { .si_status = EXIT_FAILURE };

                const struct clone_args cl_args = {
                    .flags = CLONE_VFORK | CLONE_FS | CLONE_IO | CLONE_SYSVSEM
                                         | CLONE_CLEAR_SIGHAND
                                         | CLONE_PARENT_SETTID,
                    .parent_tid = (uintptr_t)&si.si_pid,
                };

                if (cred.pid == -1 && fcntl(killfd, F_GETOWN) != -1) {
                    continue;
                }

                D(("forking plymouth boot splash."));

                switch (syscall(SYS_clone3, &cl_args, sizeof cl_args)) {
                default:
                    while (waitid(P_PID, si.si_pid, &si, WEXITED) &&
                           errno == EINTR) { }

                    if (si.si_code == CLD_EXITED && !si.si_status) {
                        msg.msg = PLY_BOOT_PROTOCOL_REQUEST_TYPE_SHOW_SPLASH;
                        ply_conv(1, msgs, &reply, &sockfd);

                        free(reply);
                        reply = NULL;

                        ioctl(STDIN_FILENO, VT_WAITACTIVE, minor(st->st_rdev));
                        break;
                    }
                    [[fallthrough]];
                case -1:
                    close(sockfd);
                    continue;

                case 0:
                    char plyd_arg0[] = "plymouthd";
                    char plyd_arg1[] = "--no-boot-log";
                    char *const plyd_argv[4] = {
                        plyd_arg0, plyd_arg1, arg2
                    };

                    signal(SIGHUP, SIG_IGN);

                    dup2(open(_PATH_DEVNULL, O_RDWR | O_CLOEXEC | O_NONBLOCK),
                         STDERR_FILENO);

                    execvp(plyd_arg0, plyd_argv);
                    syscall(SYS_exit, EXIT_FAILURE);
                }
            }

            D(("showing plymouth boot splash."));

            msg.msg_style = PAM_TEXT_INFO;
            msg.msg = arg2 + (sizeof _PATH_TTY + 2);
            ply_conv(1, msgs, &reply, &sockfd);
            free(reply);

            D(("entering conversation function."));

            count = ply_conv(num_msg, msgm, response, &sockfd);

            getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &n);
            close(sockfd);

            if (fcntl(killfd, F_GETOWN) != cred.pid) {
                fcntl(killfd, F_NOTIFY, 0);
                close(killfd);

                killfd = open(_PATH_DEV "char",
                              O_RDONLY | O_ASYNC | O_CLOEXEC | O_DIRECTORY);
                fcntl(killfd, F_SETOWN, cred.pid);
                if (!do_retain_splash) {
                    fcntl(killfd, F_SETSIG, SIGTERM);
                }
                fcntl(killfd, F_NOTIFY, DN_RENAME);
            }

            return count;
        } while (--count);
    }
#endif /* USE_PLYMOUTH */

    D(("allocating empty response structure array."));

    reply = calloc(num_msg, sizeof(struct pam_response));
    if (reply == NULL) {
	D(("no memory for responses"));
	return PAM_CONV_ERR;
    }

    D(("entering conversation function."));

    for (count=0; count < num_msg; ++count) {
	char *string=NULL;
	int nc;

	switch (msgm[count]->msg_style) {
	case PAM_PROMPT_ECHO_OFF:
	    nc = read_string(CONV_ECHO_OFF,msgm[count]->msg, &string);
	    if (nc < 0) {
		goto failed_conversation;
	    }
	    break;
	case PAM_PROMPT_ECHO_ON:
	    nc = read_string(CONV_ECHO_ON,msgm[count]->msg, &string);
	    if (nc < 0) {
		goto failed_conversation;
	    }
	    break;
	case PAM_ERROR_MSG:
	    if (fprintf(stderr,"%s\n",msgm[count]->msg) < 0) {
		goto failed_conversation;
	    }
	    break;
	case PAM_TEXT_INFO:
	    if (fprintf(stdout,"%s\n",msgm[count]->msg) < 0) {
		goto failed_conversation;
	    }
	    break;
	case PAM_BINARY_PROMPT:
	{
	    pamc_bp_t binary_prompt = NULL;

	    if (!msgm[count]->msg || !pam_binary_handler_fn) {
		goto failed_conversation;
	    }

	    PAM_BP_RENEW(&binary_prompt,
			 PAM_BP_RCONTROL(msgm[count]->msg),
			 PAM_BP_LENGTH(msgm[count]->msg));
	    PAM_BP_FILL(binary_prompt, 0, PAM_BP_LENGTH(msgm[count]->msg),
			PAM_BP_RDATA(msgm[count]->msg));

	    if (pam_binary_handler_fn(appdata_ptr,
				      &binary_prompt) != PAM_SUCCESS
		|| (binary_prompt == NULL)) {
		goto failed_conversation;
	    }
	    string = (char *) binary_prompt;
	    binary_prompt = NULL;

	    break;
	}
	default:
	    fprintf(stderr, _("erroneous conversation (%d)\n"),
		   msgm[count]->msg_style);
	    goto failed_conversation;
	}

	if (string) {                         /* must add to reply array */
	    /* add string to list of responses */

	    reply[count].resp_retcode = 0;
	    reply[count].resp = string;
	    string = NULL;
	}
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;

failed_conversation:

    D(("the conversation failed"));

    if (reply) {
	for (count=0; count<num_msg; ++count) {
	    if (reply[count].resp == NULL) {
		continue;
	    }
	    switch (msgm[count]->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
	    case PAM_PROMPT_ECHO_OFF:
		pam_overwrite_string(reply[count].resp);
		free(reply[count].resp);
		break;
	    case PAM_BINARY_PROMPT:
	      {
		void *bt_ptr = reply[count].resp;
		pam_binary_handler_free(appdata_ptr, bt_ptr);
		break;
	      }
	    case PAM_ERROR_MSG:
	    case PAM_TEXT_INFO:
		/* should not actually be able to get here... */
		free(reply[count].resp);
	    }
	    reply[count].resp = NULL;
	}
	/* forget reply too */
	free(reply);
	reply = NULL;
    }

    return PAM_CONV_ERR;
}
