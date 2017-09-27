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

static struct responses *
lookup_response(uuid_t *uuid)
{
	size_t i;

	for (i = 0; i < nresponses; i++) {
		if (responses[i].active == 0)
			continue;

		if (uuid_equal(uuid, &(responses[i].response->r_uuid), NULL)) {
			return (&responses[i]);
		}
	}

	return (NULL);
}

static void
close_resource(uuid_t *uuid)
{
	struct responses *r;

	r = lookup_response(uuid);
	if (r != NULL) {
		if (r->fd != badf)
			close(r->fd);
		free(r->response);
		memset(r, 0, sizeof(*r));
	}
}

static struct responses *
do_open(struct request *request)
{
	struct response *response;
	struct responses *res;
	int fd, flags;
	mode_t mode;

	response = calloc(1, sizeof(*response));
	if (response == NULL)
		return (NULL);

	flags = request->r_payload.u_add_file_path.r_flags;
	mode = request->r_payload.u_add_file_path.r_mode;

	if ((flags & O_CREAT) == O_CREAT) {
		fd = open(request->r_payload.u_add_file_path.r_path,
		    flags, mode);
	} else {
		fd = open(request->r_payload.u_add_file_path.r_path,
		    flags);
	}

	if (fd != -1 &&
	    (request->r_payload.u_add_file_path.r_features & F_FILE_FEATURE_CAP)) {
		cap_rights_limit(fd,
		    &(request->r_payload.u_add_file_path.r_rights));
	}

	if (fd == -1) {
		fd = badf;
		response->r_code = ERROR_FAIL;
		response->r_errno = errno;
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
	}

	if (fd == -1) {
		fd = badf;
		response->r_code = ERROR_FAIL;
		response->r_errno = errno;
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

static struct response *
do_connect(struct request *request)
{
	struct response *res;
	struct responses *r;
	struct sockaddr *p;
	int conres;

	res = calloc(1, sizeof(*res));
	if (res == NULL)
		return (NULL);

	r = lookup_response(&(request->r_payload.u_connect.r_uuid));
	if (r == NULL) {
		printf("Child: Could not lookup descriptor\n");
		res->r_code = ERROR_FAIL;
		res->r_errno = EBADF;
		return (res);
	}

	/* XXX Yeah, this sucks horribly */
	conres = -1;
	switch (request->r_payload.u_connect.r_socklen) {
	case sizeof(struct sockaddr_in):
		conres = connect(r->fd,
		    (const struct sockaddr *)(&(request->r_payload.u_connect.r_sock.addr4)),
		    request->r_payload.u_connect.r_socklen);
		break;
	case sizeof(struct sockaddr_in6):
		conres = connect(r->fd,
		    (const struct sockaddr *)(&(request->r_payload.u_connect.r_sock.addr6)),
		    request->r_payload.u_connect.r_socklen);
		break;
	default:
		printf("blargh: %zu!\n", request->r_payload.u_connect.r_socklen);
	}

	if (conres == -1) {
		perror("child connect");
		res->r_code = ERROR_FAIL;
		res->r_errno = EBADF;
		return (res);
	}

	return (res);
}

static struct response *
do_unlink_path(struct request *request)
{
	struct response *response;
	int res;

	response = calloc(1, sizeof(*response));
	if (response == NULL)
		return (NULL);

	res = unlink(request->r_payload.u_unlink_path.r_path);
	if (res) {
		response->r_code = ERROR_FAIL;
		response->r_errno = errno;
	}

	return (response);
}

static void
do_getaddrinfo(int fd, struct request *request)
{
	struct addrinfo *hints, *iter, *res;
	struct response_addrinfo *addrinfo_responses;
	char *host, *servname;
	size_t i, nresults;
	int err;

	host = servname = NULL;
	hints = NULL;
	res = NULL;

	if (strlen(request->r_payload.u_getaddrinfo.r_hostname))
		host = request->r_payload.u_getaddrinfo.r_hostname;
	if (strlen(request->r_payload.u_getaddrinfo.r_servname))
		servname = request->r_payload.u_getaddrinfo.r_servname;
	if ((request->r_payload.u_getaddrinfo.r_features & F_GETADDRINFO_HINTS))
		hints = &(request->r_payload.u_getaddrinfo.r_hints);

	if (host == NULL && servname == NULL) {
		printf("Child: Both host and servname cannot be null\n");
		/* XXX Process error */
		goto err;
	}

	err = getaddrinfo(host, servname, hints, &res);
	if (err) {
		/* XXX Process error */
		perror("child getaddrinfo");
		goto err;
	}

	iter = res;
	nresults = 0;
	while (iter != NULL) {
		iter = iter->ai_next;
		nresults++;
	}

	addrinfo_responses = calloc(nresults, sizeof(*responses));
	if (addrinfo_responses == NULL) {
		perror("Child calloc");
		nresults = 0;
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	if (send(fd, &nresults, sizeof(nresults), 0) != sizeof(nresults)) {
		freeaddrinfo(res);
		nresults = 0;
		send(fd, &nresults, sizeof(nresults), 0);
		goto err;
	}

	for (i=0, iter = res; iter != NULL; iter = iter->ai_next, i++) {
		addrinfo_responses[i].ra_flags = iter->ai_flags;
		addrinfo_responses[i].ra_family = iter->ai_family;
		addrinfo_responses[i].ra_socktype = iter->ai_socktype;
		addrinfo_responses[i].ra_protocol = iter->ai_protocol;

		switch (iter->ai_family) {
		case AF_INET:
			memmove(&(addrinfo_responses[i].ra_sockaddr.addr4),
			    iter->ai_addr,
			    sizeof(addrinfo_responses[i].ra_sockaddr.addr4));
			break;
		case AF_INET6:
			memmove(&(addrinfo_responses[i].ra_sockaddr.addr6),
			    iter->ai_addr,
			    sizeof(addrinfo_responses[i].ra_sockaddr.addr6));
			break;
		}
	}

	send(fd, addrinfo_responses, sizeof(*addrinfo_responses) * nresults, 0);

err:
	if (res != NULL)
		freeaddrinfo(res);
}

void
fork_backend(void)
{
	struct response response, *responsep;
	char control[CONTROLSZ];
	int fd, fdpair[2], newfd;
	struct request request;
	struct responses *res;
	struct cmsghdr *cmsg;
	cap_rights_t rights;
	struct msghdr msg;
	struct iovec iov;
	ssize_t nrecv;
	pid_t pid;

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
		childpid = pid;
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
		case CONNECT_SOCKET:
			responsep = do_connect(&request);
			break;
		case CLOSE_FD:
			close_resource(&(request.r_payload.u_close_fd.r_uuid));
			break;
		case UNLINK_PATH:
			responsep = do_unlink_path(&request);
			break;
		case SHUTDOWN:
			close(fd);
			_exit(0);
		case GETADDRINFO:
			do_getaddrinfo(fd, &request);
			break;
		}

		if (request.r_type == CLOSE_FD ||
		    request.r_type == GETADDRINFO)
			continue;

		if (request.r_type == CONNECT_SOCKET) {
			if (res == NULL)
				continue;

			send(fd, responsep, sizeof(*responsep), 0);
			free(responsep);
			continue;
		}

		if (request.r_type == UNLINK_PATH) {
			if (responsep == NULL) {
				/* XXX Ouch */
				continue;
			}

			if (send(fd, responsep, sizeof(*responsep), 0) != sizeof(*responsep)) {
				/* XXX Major ouch */
				close(fd);
				exit(0);
			}

			free(responsep);
			continue;
		}

		if (res == NULL) {
			memset(&response, 0, sizeof(response));
			response.r_code = ERROR_FAIL;
			response.r_errno = errno;
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
