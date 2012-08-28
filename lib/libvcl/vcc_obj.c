/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit and run generate.py instead
 */

#include "config.h"
#include <stdio.h>
#include "vcc_compile.h"

const struct var vcc_vars[] = {
	{ "client.ip", IP, 9,
	    "VRT_r_client_ip(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "client.identity", STRING, 15,
	    "VRT_r_client_identity(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_client_identity(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "server.ip", IP, 9,
	    "VRT_r_server_ip(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "server.hostname", STRING, 15,
	    "VRT_r_server_hostname(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "server.identity", STRING, 15,
	    "VRT_r_server_identity(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "server.port", INT, 11,
	    "VRT_r_server_port(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.request", STRING, 11,
	    "VRT_r_req_request(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_request(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.url", STRING, 7,
	    "VRT_r_req_url(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_url(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.proto", STRING, 9,
	    "VRT_r_req_proto(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_proto(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.http.", HEADER, 9,
	    "VRT_r_req_http_(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_http_(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "HDR_REQ",
	},
	{ "req.backend", BACKEND, 11,
	    "VRT_r_req_backend(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_backend(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.restarts", INT, 12,
	    "VRT_r_req_restarts(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.esi_level", INT, 13,
	    "VRT_r_req_esi_level(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.ttl", DURATION, 7,
	    "VRT_r_req_ttl(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_ttl(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.grace", DURATION, 9,
	    "VRT_r_req_grace(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_grace(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.keep", DURATION, 8,
	    "VRT_r_req_keep(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    "VRT_l_req_keep(sp, ",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    0,
	},
	{ "req.xid", STRING, 7,
	    "VRT_r_req_xid(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.esi", BOOL, 7,
	    "VRT_r_req_esi(sp)",
	    VCL_MET_RECV | VCL_MET_FETCH | VCL_MET_DELIVER | VCL_MET_ERROR,
	    "VRT_l_req_esi(sp, ",
	    VCL_MET_RECV | VCL_MET_FETCH | VCL_MET_DELIVER | VCL_MET_ERROR,
	    0,
	},
	{ "req.can_gzip", BOOL, 12,
	    "VRT_r_req_can_gzip(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.backend.healthy", BOOL, 19,
	    "VRT_r_req_backend_healthy(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "req.hash_ignore_busy", BOOL, 20,
	    "VRT_r_req_hash_ignore_busy(sp)",
	    VCL_MET_RECV,
	    "VRT_l_req_hash_ignore_busy(sp, ",
	    VCL_MET_RECV,
	    0,
	},
	{ "req.hash_always_miss", BOOL, 20,
	    "VRT_r_req_hash_always_miss(sp)",
	    VCL_MET_RECV,
	    "VRT_l_req_hash_always_miss(sp, ",
	    VCL_MET_RECV,
	    0,
	},
	{ "bereq.request", STRING, 13,
	    "VRT_r_bereq_request(sp)",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    "VRT_l_bereq_request(sp, ",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    0,
	},
	{ "bereq.url", STRING, 9,
	    "VRT_r_bereq_url(sp)",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    "VRT_l_bereq_url(sp, ",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    0,
	},
	{ "bereq.proto", STRING, 11,
	    "VRT_r_bereq_proto(sp)",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    "VRT_l_bereq_proto(sp, ",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    0,
	},
	{ "bereq.http.", HEADER, 11,
	    "VRT_r_bereq_http_(sp)",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    "VRT_l_bereq_http_(sp, ",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS | VCL_MET_FETCH,
	    "HDR_BEREQ",
	},
	{ "bereq.connect_timeout", DURATION, 21,
	    "VRT_r_bereq_connect_timeout(sp)",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS,
	    "VRT_l_bereq_connect_timeout(sp, ",
	    VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_MISS,
	    0,
	},
	{ "bereq.first_byte_timeout", DURATION, 24,
	    "VRT_r_bereq_first_byte_timeout(sp)",
	    VCL_MET_PASS | VCL_MET_MISS,
	    "VRT_l_bereq_first_byte_timeout(sp, ",
	    VCL_MET_PASS | VCL_MET_MISS,
	    0,
	},
	{ "bereq.between_bytes_timeout", DURATION, 27,
	    "VRT_r_bereq_between_bytes_timeout(sp)",
	    VCL_MET_PASS | VCL_MET_MISS,
	    "VRT_l_bereq_between_bytes_timeout(sp, ",
	    VCL_MET_PASS | VCL_MET_MISS,
	    0,
	},
	{ "beresp.proto", STRING, 12,
	    "VRT_r_beresp_proto(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_proto(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.saintmode", DURATION, 16,
	    NULL,	/* No reads allowed */
	    0,
	    "VRT_l_beresp_saintmode(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.status", INT, 13,
	    "VRT_r_beresp_status(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_status(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.response", STRING, 15,
	    "VRT_r_beresp_response(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_response(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.http.", HEADER, 12,
	    "VRT_r_beresp_http_(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_http_(sp, ",
	    VCL_MET_FETCH,
	    "HDR_BERESP",
	},
	{ "beresp.do_esi", BOOL, 13,
	    "VRT_r_beresp_do_esi(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_do_esi(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.do_stream", BOOL, 16,
	    "VRT_r_beresp_do_stream(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_do_stream(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.do_gzip", BOOL, 14,
	    "VRT_r_beresp_do_gzip(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_do_gzip(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.do_gunzip", BOOL, 16,
	    "VRT_r_beresp_do_gunzip(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_do_gunzip(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.ttl", DURATION, 10,
	    "VRT_r_beresp_ttl(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_ttl(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.grace", DURATION, 12,
	    "VRT_r_beresp_grace(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_grace(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.keep", DURATION, 11,
	    "VRT_r_beresp_keep(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_keep(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.backend.name", STRING, 19,
	    "VRT_r_beresp_backend_name(sp)",
	    VCL_MET_FETCH,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "beresp.backend.ip", IP, 17,
	    "VRT_r_beresp_backend_ip(sp)",
	    VCL_MET_FETCH,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "beresp.backend.port", INT, 19,
	    "VRT_r_beresp_backend_port(sp)",
	    VCL_MET_FETCH,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "beresp.storage", STRING, 14,
	    "VRT_r_beresp_storage(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_storage(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "beresp.stream_tokens", INT, 20,
	    "VRT_r_beresp_stream_tokens(sp)",
	    VCL_MET_FETCH,
	    "VRT_l_beresp_stream_tokens(sp, ",
	    VCL_MET_FETCH,
	    0,
	},
	{ "obj.proto", STRING, 9,
	    "VRT_r_obj_proto(sp)",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    "VRT_l_obj_proto(sp, ",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    0,
	},
	{ "obj.status", INT, 10,
	    "VRT_r_obj_status(sp)",
	    VCL_MET_ERROR,
	    "VRT_l_obj_status(sp, ",
	    VCL_MET_ERROR,
	    0,
	},
	{ "obj.response", STRING, 12,
	    "VRT_r_obj_response(sp)",
	    VCL_MET_ERROR,
	    "VRT_l_obj_response(sp, ",
	    VCL_MET_ERROR,
	    0,
	},
	{ "obj.hits", INT, 8,
	    "VRT_r_obj_hits(sp)",
	    VCL_MET_HIT | VCL_MET_DELIVER,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "obj.http.", HEADER, 9,
	    "VRT_r_obj_http_(sp)",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    "VRT_l_obj_http_(sp, ",
	    VCL_MET_ERROR,
	    "HDR_OBJ",
	},
	{ "obj.ttl", DURATION, 7,
	    "VRT_r_obj_ttl(sp)",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    "VRT_l_obj_ttl(sp, ",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    0,
	},
	{ "obj.grace", DURATION, 9,
	    "VRT_r_obj_grace(sp)",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    "VRT_l_obj_grace(sp, ",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    0,
	},
	{ "obj.keep", DURATION, 8,
	    "VRT_r_obj_keep(sp)",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    "VRT_l_obj_keep(sp, ",
	    VCL_MET_HIT | VCL_MET_ERROR,
	    0,
	},
	{ "obj.lastuse", DURATION, 11,
	    "VRT_r_obj_lastuse(sp)",
	    VCL_MET_HIT | VCL_MET_DELIVER | VCL_MET_ERROR,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ "resp.proto", STRING, 10,
	    "VRT_r_resp_proto(sp)",
	    VCL_MET_DELIVER,
	    "VRT_l_resp_proto(sp, ",
	    VCL_MET_DELIVER,
	    0,
	},
	{ "resp.status", INT, 11,
	    "VRT_r_resp_status(sp)",
	    VCL_MET_DELIVER,
	    "VRT_l_resp_status(sp, ",
	    VCL_MET_DELIVER,
	    0,
	},
	{ "resp.response", STRING, 13,
	    "VRT_r_resp_response(sp)",
	    VCL_MET_DELIVER,
	    "VRT_l_resp_response(sp, ",
	    VCL_MET_DELIVER,
	    0,
	},
	{ "resp.http.", HEADER, 10,
	    "VRT_r_resp_http_(sp)",
	    VCL_MET_DELIVER,
	    "VRT_l_resp_http_(sp, ",
	    VCL_MET_DELIVER,
	    "HDR_RESP",
	},
	{ "now", TIME, 3,
	    "VRT_r_now(sp)",
	    VCL_MET_RECV | VCL_MET_PIPE | VCL_MET_PASS | VCL_MET_HASH
	     | VCL_MET_MISS | VCL_MET_HIT | VCL_MET_FETCH | VCL_MET_DELIVER
	     | VCL_MET_ERROR | VCL_MET_INIT | VCL_MET_FINI,
	    NULL,	/* No writes allowed */
	    0,
	    0,
	},
	{ NULL }
};
