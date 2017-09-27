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

#ifndef _FDPASSING_H
#define _FDPASSING_H

#include <uuid.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#define	F_NONE		 0
#define	F_SHUTDOWN	 1

#define	F_FEATURE_NONE	 0
#define	F_FEATURE_CAP	 1

#define	F_GETADDRINFO_NONE	 0
#define	F_GETADDRINFO_HINTS	 1

#define	STATUSSZ	 33
#define	CONTROLSZ	 (sizeof(struct cmsghdr) + sizeof(int) + 16)

typedef enum _request_type {
	ADD_FILE_PATH	= 0,
	SHUTDOWN	= 1,
	CLOSE_FD	= 2,
	CREATE_SOCKET	= 3,
	UNLINK_PATH	= 4,
	GETADDRINFO	= 5,
	CONNECT_SOCKET	= 6,
} request_type;

typedef enum _response_code {
	ERROR_NONE	= 0,
	ERROR_FAIL	= 1,
} response_code;

struct request_add_file_path {
	char		 r_path[1024];
	int		 r_flags;
	mode_t		 r_mode;
	uint64_t	 r_features;
	cap_rights_t	 r_rights;
};

struct request_close_fd {
	uuid_t	 r_uuid;
};

struct request_open_socket {
	int		 r_domain;
	int		 r_type;
	int		 r_protocol;
	uint64_t	 r_features;
	cap_rights_t	 r_rights;
};

struct request_connect_socket {
	uuid_t		 r_uuid;
	socklen_t	 r_socklen;
	union {
		struct sockaddr_in	 addr4;
		struct sockaddr_in6	 addr6;
	}		 r_sock;
};

struct request_unlink {
	char	 r_path[1024];
};

struct request_getaddrinfo {
	char		 r_hostname[256];
	char		 r_servname[256];
	struct addrinfo	 r_hints;
	uint64_t	 r_features;
};

struct request {
	request_type	 r_type;
	union {
		struct request_add_file_path	 u_add_file_path;
		struct request_open_socket	 u_open_socket;
		struct request_close_fd		 u_close_fd;
		struct request_unlink		 u_unlink_path;
		struct request_getaddrinfo	 u_getaddrinfo;
		struct request_connect_socket	 u_connect;
	}		 r_payload;
};

struct response_addrinfo {
	int	 ra_flags;
	int	 ra_family;
	int	 ra_socktype;
	int	 ra_protocol;
	union {
		struct sockaddr_in	 addr4;
		struct sockaddr_in6	 addr6;
	}	 ra_sockaddr;
};

struct response {
	response_code	 r_code;
	int		 r_errno;
	uuid_t		 r_uuid;
};

extern int backend_fd;
extern int childpid;

int sandbox_open(const char *, int, mode_t, cap_rights_t *);
int sandbox_mkdir(const char *, mode_t);
int sandbox_unlink(const char *);
int sandbox_socket(int, int, int, cap_rights_t *);
int sandbox_getaddrinfo(const char *, const char *,
    const struct addrinfo *, struct addrinfo **);
int sandbox_connect(int, struct sockaddr *, socklen_t);

void fork_backend(void);
void sandbox_cleanup(void);

#endif /* !_FDPASSING_H */
