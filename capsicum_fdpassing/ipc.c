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

int backend_fd;

struct response_wrapper {
	int fd;
	struct response response;
};

static void
usage(char *prog)
{
	fprintf(stderr, "USAGE: %s [-s] [-f <path>]\n", prog);
	fprintf(stderr, "    -s:        Create a socket\n");
	fprintf(stderr, "    -f <path>: Open a file at path <path>\n");
	exit(0);
}

static struct response_wrapper *
send_request(struct request *request)
{
	struct response_wrapper *wrapper;
	struct response response;
	char control[CONTROLSZ];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;

	wrapper = calloc(1, sizeof(*wrapper));
	if (wrapper == NULL)
		return (NULL);

	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));

	if (send(backend_fd, request, sizeof(*request), 0) != sizeof(*request)) {
		perror("write");
		return (NULL);
	}

	switch (request->r_type) {
	case CLOSE_FD:
	case SHUTDOWN:
		free(wrapper);
		return (NULL);
	default:
		break;
	}

	iov.iov_base = &(wrapper->response);
	iov.iov_len = sizeof(wrapper->response);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (recvmsg(backend_fd, &msg, 0) < 0) {
		perror("recvmsg");
		return (NULL);
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg != NULL) {
		if (cmsg->cmsg_level == SOL_SOCKET && \
		    cmsg->cmsg_type == SCM_RIGHTS) {
			memmove(&(wrapper->fd), CMSG_DATA(cmsg),
			    sizeof(wrapper->fd));
			return (wrapper);
		}
	}

	free(wrapper);
	return (NULL);

}

static struct response_wrapper *
open_file(char *path)
{
	struct response_wrapper *wrapper;
	struct request request;
	int fd;

	memset(&request, 0, sizeof(request));

	strlcpy(request.r_payload.u_add_file_path.r_path, path,
	    sizeof(request.r_payload.u_add_file_path.r_path));
	request.r_payload.u_add_file_path.r_flags = O_RDONLY;
	request.r_payload.u_add_file_path.r_features |= F_FILE_FEATURE_CAP;
	cap_rights_init(&(request.r_payload.u_add_file_path.r_rights),
	    CAP_READ, CAP_FCNTL);

	wrapper = send_request(&request);
	return (wrapper);
}

static struct response_wrapper *
create_socket(void)
{
	struct response_wrapper *wrapper;
	struct request request;
	int fd;

	memset(&request, 0, sizeof(request));

	request.r_payload.u_open_socket.r_domain = PF_INET;
	request.r_payload.u_open_socket.r_type = SOCK_STREAM;
	request.r_payload.u_open_socket.r_features |= F_FILE_FEATURE_CAP;
	cap_rights_init(&(request.r_payload.u_open_socket.r_rights),
	    CAP_READ, CAP_WRITE, CAP_CONNECT, CAP_EVENT);

	wrapper = send_request(&request);
	return (wrapper);
}

static void
close_fd(uuid_t *uuid)
{
	struct request request;

	memset(&request, 0, sizeof(request));
	request.r_type = CLOSE_FD;
	memmove(&(request.r_payload.u_close_fd.r_uuid), uuid,
	    sizeof(request.r_payload.u_close_fd.r_uuid));

	send_request(&request);
}

void shutdown_backend(void)
{
	struct request request;

	memset(&request, 0, sizeof(request));
	request.r_type = SHUTDOWN;

	send_request(&request);

	return;
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

	while ((ch = getopt(argc, argv, "hsf:")) != -1) {
		switch (ch) {
		case 's':
			wrapper = create_socket();
			if (wrapper == NULL)
				continue;

			close_fd(&(wrapper->response.r_uuid));

			fd = wrapper->fd;

			printf("Opened a socket. fd is %d\n", fd);
			close(fd);
			free(wrapper);
			break;
		case 'f':
			wrapper = open_file(optarg);
			if (wrapper == NULL)
				continue;

			close_fd(&(wrapper->response.r_uuid));

			fd = wrapper->fd;
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
			shutdown_backend();
			usage(argv[0]);
		}
	}

end:
	shutdown_backend();
	return (0);
}
