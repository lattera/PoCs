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
int childpid;

struct response_wrapper {
	int fd;
	struct response response;
};

static struct response_wrapper *
send_request(struct request *request)
{
	struct response_wrapper *wrapper;
	char control[CONTROLSZ];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	ssize_t nrecv;

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
	case GETADDRINFO:
		free(wrapper);
		return (NULL);
	case UNLINK_PATH:
		nrecv = recv(backend_fd, &(wrapper->response),
		    sizeof(wrapper->response), 0);
		if (nrecv != sizeof(wrapper->response)) {
			free(wrapper);
			return (NULL);
		}
		return (wrapper);
	case CLOSE_FD:
	case SHUTDOWN:
		free(wrapper);
		return (NULL);
	case ADD_FILE_PATH:
	case CREATE_SOCKET:
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
open_file(const char *path, int flags, mode_t mode, cap_rights_t *rights)
{
	struct response_wrapper *wrapper;
	struct request request;

	memset(&request, 0, sizeof(request));

	strlcpy(request.r_payload.u_add_file_path.r_path, path,
	    sizeof(request.r_payload.u_add_file_path.r_path));
	if (rights != NULL) {
		request.r_payload.u_add_file_path.r_features |= F_FILE_FEATURE_CAP;
		memcpy(&(request.r_payload.u_add_file_path.r_rights), rights,
		    sizeof(request.r_payload.u_add_file_path.r_rights));
	}

	wrapper = send_request(&request);
	return (wrapper);
}

static struct response_wrapper *
create_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
	struct response_wrapper *wrapper;
	struct request request;
	int fd;

	memset(&request, 0, sizeof(request));

	request.r_type = CREATE_SOCKET;
	request.r_payload.u_open_socket.r_domain = domain;
	request.r_payload.u_open_socket.r_type = type;
	request.r_payload.u_open_socket.r_protocol = protocol;
	if (rights != NULL) {
		request.r_payload.u_open_socket.r_features |= F_FILE_FEATURE_CAP;
		memcpy(&(request.r_payload.u_open_socket.r_rights), rights,
		    sizeof(request.r_payload.u_open_socket.r_rights));
	}

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
sandbox_open(const char *path, int flags, mode_t mode,
    cap_rights_t *rights)
{
	struct response_wrapper *wrapper;
	int fd;

	fd = -1;
	wrapper = open_file(path, flags, mode, rights);
	if (wrapper == NULL)
		goto end;
	fd = wrapper->fd;

	if (wrapper->response.r_code != ERROR_NONE) {
		fd = -1;
		errno = wrapper->response.r_errno;
	}

end:
	if (wrapper != NULL) {
		if (fd != -1)
			close_fd(&(wrapper->response.r_uuid));
		free(wrapper);
	}

	return (fd);
}

int
sandbox_unlink(const char *path)
{
	struct response_wrapper *wrapper;
	struct request request;
	int res;

	memset(&request, 0, sizeof(request));

	request.r_type = UNLINK_PATH;
	strlcpy(request.r_payload.u_unlink_path.r_path, path,
	    sizeof(request.r_payload.u_unlink_path.r_path));

	wrapper = send_request(&request);
	if (wrapper == NULL)
		return (0);

	res = wrapper->response.r_code;
	if (res == ERROR_FAIL)
		errno = wrapper->response.r_errno;

	free(wrapper);
	return (res == ERROR_FAIL ? -1 : 0);
}

int
sandbox_socket(int domain, int type, int protocol,
    cap_rights_t *rights)
{
	struct response_wrapper *wrapper;
	int fd;

	wrapper = create_socket(domain, type, protocol, rights);
	if (wrapper == NULL)
		return (-1);

	fd = wrapper->fd;

	if (wrapper->response.r_code != ERROR_NONE) {
		fd = -1;
		errno = wrapper->response.r_errno;
	}

	close_fd(&(wrapper->response.r_uuid));

	free(wrapper);
	return (fd);
}


int
sandbox_getaddrinfo(const char *name, const char *servname,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
	struct response_addrinfo *responses;
	struct request request;
	struct addrinfo *next, *p;
	size_t i, nresults;
	int retval;

	if (name == NULL && servname == NULL)
		return (-1);

	retval = 0;
	memset(&request, 0, sizeof(request));
	request.r_type = GETADDRINFO;
	if (hints != NULL) {
		memmove(&(request.r_payload.u_getaddrinfo.r_hints),
		    hints,
		    sizeof(request.r_payload.u_getaddrinfo.r_hints));
		request.r_payload.u_getaddrinfo.r_features |= F_GETADDRINFO_HINTS;
	}

	if (name != NULL) {
		strlcpy(request.r_payload.u_getaddrinfo.r_hostname,
		    name,
		    sizeof(request.r_payload.u_getaddrinfo.r_hostname));
	}

	if (servname != NULL) {
		strlcpy(request.r_payload.u_getaddrinfo.r_servname,
		    servname,
		    sizeof(request.r_payload.u_getaddrinfo.r_servname));
	}

	if (send(backend_fd, &request, sizeof(request), 0) != sizeof(request)) {
		retval = -1;
		goto end;
	}

	nresults = 0;
	if (recv(backend_fd, &nresults, sizeof(nresults), 0) != sizeof(nresults)) {
		retval = -1;
		goto end;
	}

	if (nresults == 0) {
		retval = -1;
		goto end;
	}

	responses = calloc(nresults, sizeof(*responses));
	if (responses == NULL) {
		/* XXX we still have data to recv... Fix this... */
		perror("parent calloc");
		retval = -1;
		goto end;
	}

	if (recv(backend_fd, responses, sizeof(*responses) * nresults, 0)
	!= sizeof(*responses) * nresults) {
		retval = -1;
		goto end;
	}

	*res = calloc(1, sizeof(struct addrinfo));
	if (*res == NULL) {
		retval = -1;
		goto end;
	}

	p = *res;
	for (i=0; i < nresults; i++) {
		p->ai_flags = responses[i].ra_flags;
		p->ai_family = responses[i].ra_family;
		p->ai_socktype = responses[i].ra_socktype;
		p->ai_protocol = responses[i].ra_protocol;

		switch (p->ai_family) {
		case AF_INET:
			p->ai_addrlen = sizeof(struct sockaddr_in);
			p->ai_addr = malloc(p->ai_addrlen);
			if (p->ai_addr == NULL) {
				/* XXX Handle this */
				retval = -1;
				goto end;
			}
			memmove(p->ai_addr, &(responses[i].ra_sockaddr.addr4),
				p->ai_addrlen);
			break;
		case AF_INET6:
			p->ai_addrlen = sizeof(struct sockaddr_in6);
			p->ai_addr = malloc(p->ai_addrlen);
			if (p->ai_addr == NULL) {
				/* XXX Handle this */
				retval = -1;
				goto end;
			}
			memmove(p->ai_addr, &(responses[i].ra_sockaddr.addr6),
				p->ai_addrlen);
			break;
		}

		next = calloc(1, sizeof(struct addrinfo));
		if (next == NULL) {
			/* XXX Handle this */
			retval = -1;
			goto end;
		}

		p->ai_next = next;
		p = next;
	}

end:
	return (retval);
}

void
sandbox_cleanup(void)
{
	shutdown_backend();
}
