/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
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
 * The consistent hash director uses a consistent hash function on the
 * requested URL to pick a backend.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include "cache.h"
#include "cache_backend.h"
#include "vrt.h"
#include "vsha256.h"
#include "vend.h"

/*--------------------------------------------------------------------*/

struct vdi_chash_host {
	struct director		*backend;
	unsigned			weight;
};

struct vdi_chash_continuum {
	double					hash;
	struct vdi_chash_host	*host;
};

struct vdi_chash {
	unsigned		magic;
#define VDI_CHASH_MAGIC	0x61acf3f2
	struct director		dir;

	unsigned		retries;
	unsigned		tot_weight;
	struct vdi_chash_host	*hosts;
	struct vdi_chash_continuum	*continuum;
	unsigned		nhosts;
};

/*
 * Applies sha256 using the given context and input/length, and returns
 * the digest
 */

static void
vdi_chash_sha_digest(uint8_t digest[SHA256_LEN], const char *input, ssize_t len)
{
	struct SHA256Context ctx;

	AN(input);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, len);
	SHA256_Final(digest, &ctx);
	return;
}

static int
vdi_chash_cont_compare(const void *a, const void *b) {
    const double *da = (const struct vdi_chash_continuum *) a->hash;
    const double *db = (const struct vdi_chash_continuum *) b->hash;

    return (*da > *db) - (*da < *db);
}

/*
 * Returns the URL hash as a double.
 */
static double
vdi_chash_url_hash(const struct vdi_chash *vs, const struct sess *sp)
{
	AN(sp->digest);
	return (vle32dec(sp->digest) / exp2(32));
}

/*
 * Find the next closest backend compared to URL hash r [0...1[
 */
static int
vdi_chash_find_one(struct sess *sp, const struct vdi_chash *vs, double r)
{
	unsigned int left, right;
	struct vdi_chash_continuum *vc = vs->continuum;

	if (vs->tot_weight == 0)
		return (-1);
	else if (vs->tot_weight == 1
		|| r <= vc[0].hash
		|| r > vc[vs->tot_weight-1].hash)
		return (0);

	/* binary search */
	left = 0;
	right = vs->tot_weight;
	while (left+1 != right) {
		unsigned int mid = (left + right) / 2;
		if (r <= vc[mid].hash)
			right = mid;
		else
			left = mid;
	}
	/* vc[right-1] < r <= vc[right] */
	return (right);
}

/*
 * Try the specified number of times to get a backend.
 * First one according to closest hash value, after that,
 * the next closest backend that is up.
 */
static struct vbc *
vdi_chash_getfd(const struct director *d, struct sess *sp)
{
	int k, idx;
	struct vdi_chash *vs;
	double r;
	struct director *backend;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_CHASH_MAGIC);

	r = vdi_chash_url_hash(vs, sp);
	idx = vdi_chash_find_one(sp, vs, r);
	if (idx >= 0) {
		for (k = 0; k < vs->retries; k++, idx++) {
			backend = vs->continuum[idx % vs->tot_weight]->host.backend;
			if (VDI_Healthy(backend, sp))
				return (VDI_GetFd(backend, sp));
		}
	}

	return (NULL);
}

/*
 * Healthy if just a single backend is...
 */
static unsigned
vdi_chash_healthy(const struct director *d, const struct sess *sp)
{
	struct vdi_chash *vs;
	int i;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_CHASH_MAGIC);

	for (i = 0; i < vs->nhosts; i++) {
		if (VDI_Healthy(vs->hosts[i].backend, sp))
			return (1);
	}
	return (0);
}

static void
vdi_chash_fini(const struct director *d)
{
	struct vdi_chash *vs;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vs, d->priv, VDI_CHASH_MAGIC);

	free(vs->hosts);
	free(vs->continuum);
	free(vs->dir.vcl_name);
	vs->dir.magic = 0;
	FREE_OBJ(vs);
}

void
vrt_init_chash(struct cli *cli, struct director **bp, int idx,
    const void *priv)
{
	const struct vrt_dir_random *t;
	struct vdi_chash *vs;
	const struct vrt_dir_random_entry *te;
	struct vdi_chash_host *vh;
	struct vdi_chash_continuum *vc;
	int i, j;
	uint8_t digest[SHA256_LEN];
	double hash;

	ASSERT_CLI();
	(void)cli;
	t = priv;

	ALLOC_OBJ(vs, VDI_CHASH_MAGIC);
	XXXAN(vs);
	vs->hosts = calloc(sizeof *vh, t->nmember);
	XXXAN(vs->hosts);

	vs->dir.magic = DIRECTOR_MAGIC;
	vs->dir.priv = vs;
	vs->dir.name = "chash";
	REPLACE(vs->dir.vcl_name, t->name);
	vs->dir.getfd = vdi_chash_getfd;
	vs->dir.fini = vdi_chash_fini;
	vs->dir.healthy = vdi_chash_healthy;

	vs->retries = t->retries;
	if (vs->retries == 0)
		vs->retries = t->nmember;
	vh = vs->hosts;
	te = t->members;
	vs->tot_weight = 0;
	for (i = 0; i < t->nmember; i++, vh++, te++) {
		assert(te->weight > 0);
		vh->weight = te->weight;
		vs->tot_weight += vh->weight;
		vh->backend = bp[te->host];
		AN(vh->backend);
	}
	vs->nhosts = t->nmember;

	/* Create the continuum */
	vs->continuum = calloc(sizeof *vc, vs->tot_weight);
	XXXAN(vs->continuum);

	vh = vs->hosts;
	vc = vs->continuum;
	for (i = 0; i < vs->nhosts; i++, vh++) {
		vdi_chash_sha_digest(digest, vh->backend->vcl_name,
				strlen(vh->backend->vcl_name));
		/* Hash backend->vcl_name vh->weight times */
		for (j = 0; j < vh->weight; j++, vc++) {
			vdi_chash_sha_digest(digest, digest, SHA256_LEN);
			vc->hash = (vle32dec(digest) / exp2(32));
			vc->host = vh;
			AN(vh->host);
		}
	}
	qsort(vs->continuum, vs->tot_weight, sizeof(vc), vdi_chash_cont_compare);

	bp[idx] = &vs->dir;
}
