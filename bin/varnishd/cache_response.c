/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
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
 */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>

#include "cache.h"
#include "stevedore.h"
#include "vct.h"

/*--------------------------------------------------------------------*/

static void
res_dorange(const struct sess *sp, const char *r, const ssize_t content_len,
	    ssize_t *plow, ssize_t *phigh)
{
	ssize_t low, high, has_low;

	assert(sp->obj->response == 200);
	if (strncmp(r, "bytes=", 6))
		return;
	r += 6;

	/* The low end of range */
	has_low = low = 0;
	if (!vct_isdigit(*r) && *r != '-')
		return;
	while (vct_isdigit(*r)) {
		has_low = 1;
		low *= 10;
		low += *r - '0';
		r++;
	}

	if (low >= content_len)
		return;

	if (*r != '-')
		return;
	r++;

	/* The high end of range */
	if (vct_isdigit(*r)) {
		high = 0;
		while (vct_isdigit(*r)) {
			high *= 10;
			high += *r - '0';
			r++;
		}
		if (!has_low) {
			low = content_len - high;
			high = content_len - 1;
		}
	} else
		high = content_len - 1;
	if (*r != '\0')
		return;

	if (high >= content_len)
		high = content_len - 1;

	if (low > high)
		return;

	http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp,
	    "Content-Range: bytes %jd-%jd/%jd",
	    (intmax_t)low, (intmax_t)high, (intmax_t)content_len);
	http_Unset(sp->wrk->resp, H_Content_Length);
	assert(sp->wrk->res_mode & RES_LEN);
	http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp,
	    "Content-Length: %jd", (intmax_t)(1 + high - low));
	http_SetResp(sp->wrk->resp, "HTTP/1.1", 206, "Partial Content");

	*plow = low;
	*phigh = high;
}

/*--------------------------------------------------------------------*/

void
RES_BuildHttp(const struct sess *sp)
{
	char time_str[30];

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	http_ClrHeader(sp->wrk->resp);
	sp->wrk->resp->logtag = HTTP_Tx;
	http_CopyResp(sp->wrk->resp, sp->obj->http);
	http_FilterFields(sp->wrk, sp->fd, sp->wrk->resp, sp->obj->http,
	    HTTPH_A_DELIVER);

	http_Unset(sp->wrk->resp, H_Accept_Ranges);
	if (!(sp->wrk->res_mode & RES_LEN)) {
		http_Unset(sp->wrk->resp, H_Content_Length);
	} else if (params->http_range_support) {
		/* We only accept ranges if we know the length */
		http_SetHeader(sp->wrk, sp->fd, sp->wrk->resp,
		    "Accept-Ranges: bytes");
	}

	if (sp->wrk->res_mode & RES_CHUNKED)
		http_SetHeader(sp->wrk, sp->fd, sp->wrk->resp,
		    "Transfer-Encoding: chunked");

	http_Unset(sp->wrk->resp, H_Date);
	TIM_format(TIM_real(), time_str);
	http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp, "Date: %s", time_str);

	if (sp->xid != sp->obj->xid)
		http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp,
		    "X-Varnish: %u %u", sp->xid, sp->obj->xid);
	else
		http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp,
		    "X-Varnish: %u", sp->xid);
	http_Unset(sp->wrk->resp, H_Age);
	http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp, "Age: %.0f",
	    sp->obj->exp.age + sp->t_resp - sp->obj->exp.entered);
	http_SetHeader(sp->wrk, sp->fd, sp->wrk->resp, "Via: 1.1 varnish");
	http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp, "Connection: %s",
	    sp->doclose ? "close" : "keep-alive");
}

/*--------------------------------------------------------------------
 * We have a gzip'ed object and need to ungzip it for a client which
 * does not understand gzip.
 * XXX: handle invalid gzip data better (how ?)
 */

static void
res_WriteGunzipObj(struct sess *sp)
{
	struct storage *st;
	unsigned u = 0;
	struct vgz *vg;
	char obuf[params->gzip_stack_buffer];
	ssize_t obufl = 0;
	int i;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	vg = VGZ_NewUngzip(sp, "U D -");

	VGZ_Obuf(vg, obuf, sizeof obuf);
	VTAILQ_FOREACH(st, &sp->obj->store, list) {
		CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		CHECK_OBJ_NOTNULL(st, STORAGE_MAGIC);
		u += st->len;

		VSC_C_main->n_objwrite++;

		i = VGZ_WrwGunzip(sp, vg,
		    st->ptr, st->len,
		    obuf, sizeof obuf, &obufl);
		/* XXX: error check */
		(void)i;
	}
	if (obufl) {
		sp->wrk->acct_tmp.bodybytes += obufl;
		(void)WRW_Write(sp->wrk, obuf, obufl);
		(void)WRW_Flush(sp->wrk);
	}
	(void)VGZ_Destroy(&vg);
	assert(u == sp->obj->len);
}

/*--------------------------------------------------------------------*/

static void
res_WriteDirObj(const struct sess *sp, ssize_t low, ssize_t high)
{
	ssize_t u = 0;
	size_t ptr, off, len;
	struct storage *st;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	ptr = 0;
	VTAILQ_FOREACH(st, &sp->obj->store, list) {
		CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		CHECK_OBJ_NOTNULL(st, STORAGE_MAGIC);
		u += st->len;
		len = st->len;
		off = 0;
		if (ptr + len <= low) {
			/* This segment is too early */
			ptr += len;
			continue;
		}
		if (ptr < low) {
			/* Chop front of segment off */
			off += (low - ptr);
			len -= (low - ptr);
			ptr += (low - ptr);
		}
		if (ptr + len > high)
			/* Chop tail of segment off */
			len = 1 + high - ptr;

		ptr += len;

		sp->wrk->acct_tmp.bodybytes += len;
#ifdef SENDFILE_WORKS
		/*
		 * XXX: the overhead of setting up sendfile is not
		 * XXX: epsilon and maybe not even delta, so avoid
		 * XXX: engaging sendfile for small objects.
		 * XXX: Should use getpagesize() ?
		 */
		if (st->fd >= 0 &&
		    st->len >= params->sendfile_threshold) {
			VSC_C_main->n_objsendfile++;
			WRW_Sendfile(sp->wrk, st->fd, st->where + off, len);
			continue;
		}
#endif /* SENDFILE_WORKS */
		VSC_C_main->n_objwrite++;
		(void)WRW_Write(sp->wrk, st->ptr + off, len);
	}
	assert(u == sp->obj->len);
}

/*--------------------------------------------------------------------
 * Deliver an object.
 * Attempt optimizations like 304 and 206 here.
 */

void
RES_WriteObj(struct sess *sp)
{
	char *r;
	ssize_t low, high;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	WRW_Reserve(sp->wrk, &sp->fd);

	if (sp->obj->response == 200 &&
	    sp->http->conds &&
	    RFC2616_Do_Cond(sp)) {
		sp->wantbody = 0;
		http_SetResp(sp->wrk->resp, "HTTP/1.1", 304, "Not Modified");
		http_Unset(sp->wrk->resp, H_Content_Length);
		http_Unset(sp->wrk->resp, H_Transfer_Encoding);
	}

	/*
	 * If nothing special planned, we can attempt Range support
	 */
	low = 0;
	high = sp->obj->len - 1;
	if (
	    sp->wantbody &&
	    (sp->wrk->res_mode & RES_LEN) &&
	    !(sp->wrk->res_mode & (RES_ESI|RES_ESI_CHILD|RES_GUNZIP)) &&
	    params->http_range_support &&
	    sp->obj->response == 200 &&
	    http_GetHdr(sp->http, H_Range, &r))
		res_dorange(sp, r, sp->obj->len, &low, &high);

	/*
	 * Always remove C-E if client don't grok it
	 */
	if (sp->wrk->res_mode & RES_GUNZIP)
		http_Unset(sp->wrk->resp, H_Content_Encoding);

	/*
	 * Send HTTP protocol header, unless interior ESI object
	 */
	if (!(sp->wrk->res_mode & RES_ESI_CHILD))
		sp->wrk->acct_tmp.hdrbytes +=
		    http_Write(sp->wrk, sp->wrk->resp, 1);

	if (!sp->wantbody)
		sp->wrk->res_mode &= ~RES_CHUNKED;

	if (sp->wrk->res_mode & RES_CHUNKED)
		WRW_Chunked(sp->wrk);

	if (!sp->wantbody) {
		/* This was a HEAD or conditional request */
	} else if (sp->obj->len == 0) {
		/* Nothing to do here */
	} else if (sp->wrk->res_mode & RES_ESI) {
		ESI_Deliver(sp);
	} else if (sp->wrk->res_mode & RES_ESI_CHILD && sp->wrk->gzip_resp) {
		ESI_DeliverChild(sp);
	} else if (sp->wrk->res_mode & RES_ESI_CHILD &&
	    !sp->wrk->gzip_resp && sp->obj->gziped) {
		res_WriteGunzipObj(sp);
	} else if (sp->wrk->res_mode & RES_GUNZIP) {
		res_WriteGunzipObj(sp);
	} else {
		res_WriteDirObj(sp, low, high);
	}

	if (sp->wrk->res_mode & RES_CHUNKED &&
	    !(sp->wrk->res_mode & RES_ESI_CHILD))
		WRW_EndChunk(sp->wrk);

	if (WRW_FlushRelease(sp->wrk))
		vca_close_session(sp, "remote closed");
}

/*--------------------------------------------------------------------*/

void
RES_StreamStart(struct sess *sp, ssize_t *plow, ssize_t *phigh)
{
	char *r;
	ssize_t content_len;

	AZ(sp->wrk->res_mode & RES_ESI_CHILD);

	WRW_Reserve(sp->wrk, &sp->fd);

	if (sp->obj->response == 200 &&
	    sp->http->conds &&
	    RFC2616_Do_Cond(sp)) {
		sp->wantbody = 0;
		http_SetResp(sp->wrk->resp, "HTTP/1.1", 304, "Not Modified");
		http_Unset(sp->wrk->resp, H_Content_Length);
		http_Unset(sp->wrk->resp, H_Transfer_Encoding);
	}

	/*
	 * If nothing special planned, we can attempt Range support
	 */
	if (sp->wantbody &&
	    (sp->wrk->res_mode & RES_LEN) &&
	    !(sp->wrk->res_mode &
	      (RES_ESI|RES_ESI_CHILD|RES_GUNZIP|RES_CHUNKED)) &&
	    params->http_range_support &&
	    sp->obj->response == 200 &&
	    sp->wrk->h_content_length != NULL &&
	    http_GetHdr(sp->http, H_Range, &r)) {
		/* We don't have sp->obj->len in streaming mode, so
		 * we'll have to parse the response's Content-Length
		 * header
		 */
		content_len = strtol(sp->wrk->h_content_length, NULL, 10);
		if (content_len >= 0 && content_len != LONG_MAX)
			res_dorange(sp, r, content_len, plow, phigh);
	}

	/*
	 * Always remove C-E if client don't grok it
	 */
	if (sp->wrk->res_mode & RES_GUNZIP)
		http_Unset(sp->wrk->resp, H_Content_Encoding);

	if (!sp->wantbody)
		sp->wrk->res_mode &= ~RES_CHUNKED;

	if (!(sp->wrk->res_mode & RES_CHUNKED) &&
	    sp->wrk->h_content_length != NULL &&
	    sp->wantbody &&
	    *phigh == -1) {
		http_Unset(sp->wrk->resp, H_Content_Length);
		http_PrintfHeader(sp->wrk, sp->fd, sp->wrk->resp,
		    "Content-Length: %s", sp->wrk->h_content_length);
	}

	sp->wrk->acct_tmp.hdrbytes +=
	    http_Write(sp->wrk, sp->wrk->resp, 1);

	if (sp->wrk->res_mode & RES_CHUNKED)
		WRW_Chunked(sp->wrk);
}

/*--------------------------------------------------------------------
 * Callback from the cache_fetch functions to notify new data
 * 
 * Returns 1 if the backend connection should be closed
 */

int
RES_StreamPoll(const struct sess *sp)
{
	struct busyobj *bo = NULL;
	struct storage *st;
	int r = 0;

	if (sp->stream_busyobj == NULL)
		return (0);
	bo = sp->stream_busyobj;
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);

	Lck_Lock(&bo->mtx);
	assert(sp->obj->len >= bo->stream_max);
	bo->stream_max = sp->obj->len;
	bo->stream_tokens = bo->stream_tokens_quota;
	if ((sp->obj->objcore == NULL ||
	     (sp->obj->objcore->flags & OC_F_PASS)) &&
	    bo->stream_refcnt == 0) {
		/* Is pass and we've lost our audience - close backend
		   connection */
		bo->can_stream = 0;
		r = 1;
	}
	pthread_cond_broadcast(&bo->cond_data);
	Lck_Unlock(&bo->mtx);

	if (bo->stream_frontchunk == NULL)
		return (r);

	/* It's a pass - remove chunks up til stream_frontchunk */
	assert(sp->obj->objcore == NULL ||
	       (sp->obj->objcore->flags & OC_F_PASS));
	while (1) {
		st = VTAILQ_FIRST(&sp->obj->store);
		if (st == NULL || st == bo->stream_frontchunk)
			break;
		VTAILQ_REMOVE(&sp->obj->store, st, list);
		STV_free(st);
	}
	return (r);
}

void
RES_StreamWrite(const struct sess *sp)
{
	struct stream_ctx *sctx;
	struct storage *st;
	ssize_t l, l2, stlen;
	void *ptr;

	sctx = sp->wrk->sctx;
	CHECK_OBJ_NOTNULL(sctx, STREAM_CTX_MAGIC);

	if (sctx->stream_next == sctx->stream_max)
		return;

	l = sctx->stream_front;
	st = sctx->stream_frontchunk;
	if (st == NULL)
		st = VTAILQ_FIRST(&sp->obj->store);
	CHECK_OBJ_NOTNULL(st, STORAGE_MAGIC);

	while (sctx->stream_next < sctx->stream_max) {
		stlen = (*(volatile unsigned *)&st->len);
		if (l + stlen == sctx->stream_next) {
			l += stlen;
			st = VTAILQ_NEXT(st, list);
			CHECK_OBJ_NOTNULL(st, STORAGE_MAGIC);
			stlen = (*(volatile unsigned *)&st->len);
		}
		assert(l <= sctx->stream_next);
		assert(l + stlen > sctx->stream_next);

		l2 = l + stlen - sctx->stream_next;
		if (sctx->stream_next + l2 > sctx->stream_max)
			l2 = sctx->stream_max - sctx->stream_next;
		if (sctx->stream_next < sctx->stream_start &&
		    sctx->stream_next + l2 > sctx->stream_start)
			/* Align on range start */
			l2 = sctx->stream_start - sctx->stream_next;
		else if (sctx->stream_next < sctx->stream_end &&
		    sctx->stream_next + l2 > sctx->stream_end)
			/* Align on range end */
			l2 = sctx->stream_end - sctx->stream_next;
		assert(l2 > 0);
		assert(l2 <= stlen);
		assert(sctx->stream_next + l2 <= sctx->stream_max);

		if (sctx->stream_next >= sctx->stream_start &&
		    sctx->stream_next < sctx->stream_end) {
			/* In range - write data */
			assert(sctx->stream_next + l2 <= sctx->stream_end);
			ptr = st->ptr + (sctx->stream_next - l);
			if (sp->wrk->res_mode & RES_GUNZIP)
				(void)VGZ_WrwGunzip(sp, sctx->vgz, ptr, l2,
				    sctx->obuf, sctx->obuf_len,
				    &sctx->obuf_ptr);
			else {
				(void)WRW_Write(sp->wrk, ptr, l2);
				sp->wrk->acct_tmp.bodybytes += l2;
			}
		}
		sctx->stream_next += l2;
		if (sctx->stream_next == sctx->stream_end)
			break;
	}
	sctx->stream_front = l;
	sctx->stream_frontchunk = st;

	if (!(sp->wrk->res_mode & RES_GUNZIP))
		(void)WRW_Flush(sp->wrk);

	if (sp->obj->objcore == NULL ||
	    (sp->obj->objcore->flags & OC_F_PASS)) {
		/*
		 * This is a pass object, notify fetching thread of
		 * our current chunk and it will delete the ones
		 * before it
		 */
		CHECK_OBJ_NOTNULL(sp->stream_busyobj, BUSYOBJ_MAGIC);
		sp->stream_busyobj->stream_frontchunk = sctx->stream_frontchunk;
	}
}

void
RES_StreamEnd(struct sess *sp)
{
	if (sp->wrk->res_mode & RES_CHUNKED &&
	    !(sp->wrk->res_mode & RES_ESI_CHILD))
		WRW_EndChunk(sp->wrk);
	if (WRW_FlushRelease(sp->wrk))
		vca_close_session(sp, "remote closed");
}

/* Token strategy: There is a quota of tokens issued each time new data
 * arrives on the boject. Any thread needing to wait for more data will,
 * if they can grab a token, wait for broadcast on bo->cond_data. This
 * limits the number of threads actively waiting for the broadcast to the
 * token quota.
 *
 * Threads not getting a token, will wait for a signal on
 * bo->cond_queue. Any thread that at any point was waiting for data, will
 * do a signal on this cond after the next write. This will ensure a
 * trickle of wakes also for threads on the queue_cond, while still
 * preventing a horde of threads on each new piece of data.
 */

void
RES_StreamBody(struct sess *sp, const ssize_t low, const ssize_t high)
{
	struct stream_ctx sctx;
	struct busyobj *bo;
	uint8_t obuf[sp->wrk->res_mode & RES_GUNZIP ?
		     params->gzip_stack_buffer : 1];
	int do_signal = 0;

	bo = sp->stream_busyobj;
	CHECK_OBJ_NOTNULL(bo, BUSYOBJ_MAGIC);
	AN(sp->wantbody);

	sp->wrk->acct_tmp.stream++;

	memset(&sctx, 0, sizeof sctx);
	sctx.magic = STREAM_CTX_MAGIC;
	AZ(sp->wrk->sctx);
	sp->wrk->sctx = &sctx;

	sctx.stream_start = low;
	if (high == -1)
		sctx.stream_end = SSIZE_MAX;
	else
		sctx.stream_end = high + 1;
	assert(sctx.stream_end - sctx.stream_start > 0);

	if (sp->wrk->res_mode & RES_GUNZIP) {
		sctx.vgz = VGZ_NewUngzip(sp, "U S -");
		sctx.obuf = obuf;
		sctx.obuf_len = sizeof (obuf);
	}

	/* Invariant:
	 *	sctx.stream_max <= bo->stream_max
	 *	sctx.stream_next <= sctx.stream_max
	 *	0 <= stream_start < stream_end <= SSIZE_MAX
	 */

	Lck_Lock(&bo->mtx);
	while (!bo->stream_stop || sctx.stream_next < bo->stream_max) {
		if (WRW_Error(sp->wrk))
			break;
		if (sctx.stream_next == sctx.stream_end)
			break;

		assert(sctx.stream_max <= bo->stream_max);
		sctx.stream_max = bo->stream_max;
		assert(sctx.stream_next <= sctx.stream_max);

		Lck_Unlock(&bo->mtx);
		RES_StreamWrite(sp);
		Lck_Lock(&bo->mtx);

		if (do_signal) {
			AZ(pthread_cond_signal(&bo->cond_queue));
			do_signal = 0;
		}

		while (!bo->stream_stop && sctx.stream_max == bo->stream_max) {
			do_signal = 1;
			if (bo->stream_tokens > 0) {
				/* Tokens available, take one and wait for
				   broadcast on cond_data */
				bo->stream_tokens--;
				Lck_CondWait(&bo->cond_data, &bo->mtx);
			} else {
				/* No token available, wait on queue */
				Lck_CondWait(&bo->cond_queue, &bo->mtx);
			}
		}
	}
	if (bo->stream_error)
		sp->doclose = "Stream error";
	if (do_signal)
		AZ(pthread_cond_signal(&bo->cond_queue));
	Lck_Unlock(&bo->mtx);

	if (sp->wrk->res_mode & RES_GUNZIP) {
		if (sctx.obuf_ptr > 0)
			(void)WRW_Write(sp->wrk, sctx.obuf, sctx.obuf_ptr);
		VGZ_Destroy(&sctx.vgz);
	}

	sp->wrk->sctx = NULL;

}
