/*-
 * Copyright (c) 2013 Wikimedia Foundation
 * All rights reserved.
 *
 * Author: Mark Bergsma <mark@wikimedia.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * PROXY protocol handling
 */

#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "cache.h"

const char v2sig[13] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x02";

struct proxy_v2 {
	struct {
		uint8_t sig[12];
		uint8_t ver;
		uint8_t cmd;
		uint8_t fam;
		uint8_t len;
	} hdr;
	union {
		struct { /* for TCP/UDP over IPv4, len = 12 */
			uint32_t src_addr;
			uint32_t dst_addr;
			uint16_t src_port;
			uint16_t dst_port;
		} ip4;
		struct { /* for TCP/UDP over IPv6, len = 36 */
			uint8_t src_addr[16];
			uint8_t dst_addr[16];
			uint16_t src_port;
			uint16_t dst_port;
		} ip6;
	} addr;
};

struct proxy_state {
	unsigned		magic;
#define PROXY_STATE_MAGIC		0xE3D85857
	int valid;
	socklen_t client_addr_len;
	socklen_t server_addr_len;
	struct sockaddr_storage client_addr;
	struct sockaddr_storage server_addr;

	struct proxy_v2 *proxy_hdr;
};

struct proxy_state *
Proxy_Init(struct sess *sp) {
	struct proxy_state *ps;

	ps = (struct proxy_state *)WS_Alloc(sp->ws, sizeof *ps);
	if (ps == NULL)
		return (NULL);
	memset(ps, 0, sizeof *ps);
	ps->magic = PROXY_STATE_MAGIC;
	if (WS_Reserve(sp->ws, PRNDUP(sizeof(struct proxy_v2))) < sizeof(struct proxy_v2)) {
		WS_Reset(sp->ws, (char *)ps);
		return (NULL);
	}
	ps->proxy_hdr = (struct proxy_v2 *)sp->ws->f;
	sp->ps = ps;
	return (ps);
}

void
Proxy_Finish(struct sess *sp) {
	CHECK_OBJ_NOTNULL(sp->ps, PROXY_STATE_MAGIC);
	if (sp->ps->proxy_hdr) {
		WS_Release(sp->ws, 0);
		sp->ps->proxy_hdr = NULL;
	}
}

/*--------------------------------------------------------------------
 * Read PROXY protocol header
 * Returns:
 *	-1 error, disconnect
 *	>0 proxy header received, return number of bytes read
 */
int
Proxy_Read(const struct sess *sp) {
	struct proxy_v2 *phdr;
	struct pollfd pfd[1];
	int msgsize;

	CHECK_OBJ_NOTNULL(sp->ps, PROXY_STATE_MAGIC);
	phdr = sp->ps->proxy_hdr;

	/* Wait until we have data */
	if (params->proxy_protocol_timeout > 0) {
		pfd[0].fd = sp->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (poll(pfd, 1, params->proxy_protocol_timeout) != 1)
			return (-1);
	}

	/* Read the PROXY header */
	if (recv(sp->fd, phdr, sizeof *phdr, MSG_PEEK) >= sizeof (phdr->hdr)
		&& memcmp(phdr->hdr.sig, v2sig, sizeof v2sig) == 0
		&& phdr->hdr.len <= sizeof phdr->addr) {
		msgsize = sizeof phdr->hdr + phdr->hdr.len;
		assert(msgsize <= sizeof *phdr);
		if (read(sp->fd, phdr, msgsize) == msgsize) /* Read appropriate nr of bytes from the socket */
			return (msgsize);
	}
	return (-1);
}

int
Proxy_Parse(struct sess *sp) {
	struct proxy_v2 *phdr;

	CHECK_OBJ_NOTNULL(sp->ps, PROXY_STATE_MAGIC);
	phdr = sp->ps->proxy_hdr;

	switch (phdr->hdr.cmd) {
	case 0x01: /* PROXY command */
		switch (phdr->hdr.fam) {
		case 0x11: /* TCPv4 */
			if (phdr->hdr.len < sizeof phdr->addr.ip4)
				return (-1);
			sp->ps->client_addr_len = sp->ps->server_addr_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *) &sp->ps->client_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &sp->ps->client_addr)->sin_addr.s_addr =
					phdr->addr.ip4.src_addr;
			((struct sockaddr_in *) &sp->ps->client_addr)->sin_port = phdr->addr.ip4.src_port;
			((struct sockaddr_in *) &sp->ps->server_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &sp->ps->server_addr)->sin_addr.s_addr =
					phdr->addr.ip4.dst_addr;
			((struct sockaddr_in *) &sp->ps->server_addr)->sin_port = phdr->addr.ip4.dst_port;
			sp->ps->valid = 1;
			break;
		case 0x21: /* TCPv6 */
			if (phdr->hdr.len < sizeof phdr->addr.ip6)
				return (-1);
			sp->ps->client_addr_len = sp->ps->server_addr_len = sizeof(struct sockaddr_in6);
			((struct sockaddr_in6 *) &sp->ps->client_addr)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *) &sp->ps->client_addr)->sin6_addr,
					phdr->addr.ip6.src_addr, 16);
			((struct sockaddr_in6 *) &sp->ps->client_addr)->sin6_port =
					phdr->addr.ip6.src_port;
			((struct sockaddr_in6 *) &sp->ps->server_addr)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6 *) &sp->ps->server_addr)->sin6_addr,
					phdr->addr.ip6.dst_addr, 16);
			((struct sockaddr_in6 *) &sp->ps->server_addr)->sin6_port =
					phdr->addr.ip6.dst_port;
			sp->ps->valid = 1;
			break;
		}
		/* Error or unsupported protocol, keep local connection address */
		break;
	case 0x00: /* LOCAL command */
		/* Use local connection address for LOCAL */
		sp->ps->client_addr_len = sp->sockaddrlen;
		sp->ps->server_addr_len = sp->mysockaddrlen;
		memcpy(&sp->ps->client_addr, sp->sockaddr, sizeof(struct sockaddr_storage));
		memcpy(&sp->ps->server_addr, sp->mysockaddr, sizeof(struct sockaddr_storage));
		sp->ps->valid = 1;
		break;
	}
	return (sp->ps->valid ? 0 : -1);
}

inline struct proxy_state *
Proxy_State(const struct sess *sp) {
	if (sp->ps == NULL)
		return (NULL);

	CHECK_OBJ_NOTNULL(sp->ps, PROXY_STATE_MAGIC);
	return (sp->ps);
}

/* --------------------------------------------------------------------------
 */

unsigned Proxy_Valid(const struct sess *sp) {
	return (sp->ps != NULL && Proxy_State(sp)->valid);
}

struct sockaddr_storage *
Proxy_Client_Address(const struct sess *sp) {
	return (Proxy_Valid(sp) ? &Proxy_State(sp)->client_addr : sp->sockaddr);
}

struct sockaddr_storage *
Proxy_Server_Address(const struct sess *sp) {
	return (Proxy_Valid(sp) ? &Proxy_State(sp)->server_addr : sp->mysockaddr);
}

int Proxy_Client_Port(const struct sess *sp) {
	return (VTCP_port(Proxy_Valid(sp) ? &Proxy_State(sp)->client_addr : sp->sockaddr));
}

int Proxy_Server_Port(const struct sess *sp) {
	return (VTCP_port(Proxy_Valid(sp) ? &Proxy_State(sp)->server_addr : sp->mysockaddr));
}
