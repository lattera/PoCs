/*-
 * Copyright (c) 2017 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/capsicum.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#include "fdpassing.h"

static void
usage(char *prog)
{
	fprintf(stderr, "USAGE: %s [-s] [-f <path>]\n", prog);
	fprintf(stderr, "    -s:        Create a socket\n");
	fprintf(stderr, "    -f <path>: Open a file at path <path>\n");
	exit(0);
}

static void
sighandler(int signo)
{
	sandbox_cleanup();
	printf("Killing pid %d\n", childpid);
	kill(childpid, SIGINT);
	waitpid(childpid, NULL, 0);
	exit(0);
}

static void
handle_socket(char *arg)
{
	struct addrinfo hints, *res;
	cap_rights_t rights;
	char *port;
	int fd;

	port = strchr(arg, ':');
	if (port != NULL)
		*port++ = '\0';
	else
		port = "22";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (sandbox_getaddrinfo(arg, port, &hints, &res)) {
		perror("getaddrinfo");
		return;
	}

	cap_rights_init(&rights, CAP_CONNECT, CAP_GETPEERNAME,
	    CAP_RECV, CAP_SEND, CAP_SETSOCKOPT, CAP_SHUTDOWN,
	    CAP_GETSOCKNAME, CAP_PEELOFF);

	fd = sandbox_socket(res->ai_family, res->ai_socktype,
	    res->ai_protocol, &rights);
	if (fd == -1) {
		perror("sandbox_socket");
		return;
	}

	if (connect(fd, res->ai_addr, res->ai_addrlen)) {
		perror("connect");
		return;
	}

	close(fd);
}

int
main(int argc, char *argv[])
{
	struct response_wrapper *wrapper;
	char buf[1024], *p;
	int ch, fd, i;
	FILE *fp;

	fork_backend();
	cap_enter();

	signal(SIGINT, sighandler);

	while ((ch = getopt(argc, argv, "hf:s:")) != -1) {
		switch (ch) {
		case 's':
			handle_socket(optarg);
			break;
		case 'f':
			fd = sandbox_open(optarg, O_RDONLY, 0, NULL);
			if (fd == -1) {
				perror("sandbox_open");
				break;
			}
			fp = fdopen(fd, "r");
			if (fp == NULL) {
				perror("fdopen");
				close(fd);
				continue;
			}

			while (fgets(buf, sizeof(buf), fp))
				printf("%s", buf);

			close(fd);
			free(wrapper);
			break;
		default:
			sandbox_cleanup();
			usage(argv[0]);
		}
	}

end:
	sandbox_cleanup();
	return (0);
}
