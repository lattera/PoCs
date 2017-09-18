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

static struct responses {
	int active;
	int fd;
	struct response *response;
} *responses;

static size_t nresponses;
static int badf;

static struct responses *
add_response(int fd, struct response *response)
{
	size_t i;
	void *p;

	for (i = 0; i < nresponses; i++) {
		if (responses[i].active == 0) {
			responses[i].active = 1;
			responses[i].response = response;
			responses[i].fd = fd;
			return (&(responses[i]));
		}
	}

	p = realloc(responses, sizeof(struct responses) *
	    (nresponses + 1));
	if (p == NULL)
		return (NULL);

	responses = p;
	responses[nresponses].active = 1;
	responses[nresponses].fd = fd;
	responses[nresponses].response = response;
	nresponses++;

	return (&(responses[nresponses-1]));
}

static void
close_resource(uuid_t *uuid)
{
	size_t i;

	for (i = 0; i < nresponses; i++) {
		if (responses[i].active == 0)
			continue;

		if (uuid_equal(uuid, &(responses[i].response->r_uuid), NULL)) {
			if (responses[i].fd != badf)
				close(responses[i].fd);
			free(responses[i].response);
			memset(&responses[i], 0, sizeof(*responses));
			return;
		}
	}
}

static struct responses *
do_open(struct request *request)
{
	struct response *response;
	struct responses *res;
	int fd;

	response = calloc(1, sizeof(*response));
	if (response == NULL)
		return (NULL);

	fd = open(request->r_payload.u_add_file_path.r_path,
	    request->r_payload.u_add_file_path.r_flags);
	if (fd != -1 &&
	    (request->r_payload.u_add_file_path.r_features & F_FILE_FEATURE_CAP)) {
		cap_rights_limit(fd,
		    &(request->r_payload.u_add_file_path.r_rights));
		strlcpy(response->r_status, "OK", sizeof(response->r_status));
	}

	if (fd == -1) {
		fd = badf;
		strlcpy(response->r_status, "FAIL", sizeof(response->r_status));
	}

	uuidgen(&(response->r_uuid), 1);
	res = add_response(fd, response);
	if (res == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		free(response);
		return (NULL);
	}

	return (res);
}

static struct responses *
do_socket_create(struct request *request)
{
	struct response *response;
	struct responses *res;
	int fd;

	response = calloc(1, sizeof(*response));
	if (response == NULL)
		return (NULL);

	fd = socket(request->r_payload.u_open_socket.r_domain,
	    request->r_payload.u_open_socket.r_type,
	    request->r_payload.u_open_socket.r_protocol);
	if (fd != -1 &&
	    (request->r_payload.u_open_socket.r_features & F_FILE_FEATURE_CAP)) {
		cap_rights_limit(fd,
		    &(request->r_payload.u_open_socket.r_rights));
		strlcpy(response->r_status, "OK", sizeof(response->r_status));
	}

	if (fd == -1) {
		fd = badf;
		strlcpy(response->r_status, "FAIL", sizeof(response->r_status));
	}

	uuidgen(&(response->r_uuid), 1);
	res = add_response(fd, response);
	if (res == NULL) {
		close(fd);
		memset(response, 0, sizeof(*response));
		free(response);
		return (NULL);
	}

	return (res);
}

void
fork_backend(void)
{
	char buffer[sizeof(struct request)];
	char control[CONTROLSZ];
	int fd, fdpair[2], newfd;
	struct response response;
	struct request request;
	struct responses *res;
	struct cmsghdr *cmsg;
	cap_rights_t rights;
	struct msghdr msg;
	struct iovec iov;
	ssize_t nrecv;
	pid_t pid;
	size_t i;

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fdpair)) {
		perror("socketpair");
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		badf = open("/dev/null", O_RDONLY);
		close(fdpair[0]);
		fd = fdpair[1];
		daemon(0, 1);
		break;
	default:
		cap_rights_init(&rights, CAP_READ, CAP_WRITE);
		backend_fd = fdpair[0];
		cap_rights_limit(backend_fd, &rights);
		close(fdpair[1]);
		return;
	}

	while (1) {
		memset(&request, 0, sizeof(request));
		memset(&response, 0, sizeof(response));
		memset(&iov, 0, sizeof(iov));
		memset(&msg, 0, sizeof(msg));
		memset(&control, 0, sizeof(control));

		nrecv = recv(fd, &request, sizeof(request), 0);
		if (nrecv < 0) {
			perror("recv");
			close(fd);
			_exit(1);
		}

		switch (request.r_type) {
		case ADD_FILE_PATH:
			res = do_open(&request);
			break;
		case CREATE_SOCKET:
			res = do_socket_create(&request);
			break;
		case CLOSE_FD:
			close_resource(&(request.r_payload.u_close_fd.r_uuid));
			break;
		case SHUTDOWN:
			close(fd);
			_exit(0);
		}

		if (request.r_type == CLOSE_FD)
			continue;

		if (res == NULL) {
			memset(&response, 0, sizeof(response));
			strlcpy(response.r_status, "FAIL", sizeof(response.r_status));
			newfd = -1;
		} else {
			memmove(&response, res->response, sizeof(response));
			newfd = res->fd;
		}

		iov.iov_base = &response;
		iov.iov_len = sizeof(response);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		memmove(CMSG_DATA(cmsg), &newfd, sizeof(newfd));
		msg.msg_controllen = cmsg->cmsg_len;

		if (sendmsg(fd, &msg, 0) < 0) {
			perror("sendmsg");
			_exit(0);
		}
	}

	_exit(0);
}
