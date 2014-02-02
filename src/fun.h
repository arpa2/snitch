/* snitch/fun.h -- Structures and function prototypes
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


/********** STRUCTURES **********/


/* Distinguish indexes into the pollfd sequence as a special type. */
typedef unsigned int pollidx_t;
#define INVALID_POLLIDX ((pollidx_t) -1)


/* A configured mapping, labeled and with a particular downlink. */
struct mapping {
	struct mapping *next;
	char *label;
	struct in6_addr fwdaddr;
	uint16_t fwdport;
};

#define MAXRECLEN (5 + 16384)

#define PROXY_MODE_MASK		0x000f
#define PROXY_MODE_RECV		0x0000
#define PROXY_MODE_SEND		0x0001
#define PROXY_MODE_ERROR	0x0003

#define PROXY_SIDE_UPSTREAM	0x0010

#define set_proxymode(pxy,m) (((pxy)->flags = ((pxy)->flags & ~PROXY_MODE_MASK) | (m)))
#define proxymode(pxy,m) ((pxy)->flags & ~PROXY_MODE_MASK)

#define init_dnstream_proxy(pxy) { (pxy)->flags = PROXY_MODE_RECV; }
#define init_upstream_proxy(pxy) { (pxy)->flags = PROXY_MODE_RECV | PROXY_SIDE_UPSTREAM; }

#define proxy_sends(pxy) (((pxy)->flags & PROXY_MODE_MASK) == PROXY_MODE_SEND)
#define proxy_recvs(pxy) (((pxy)->flags & PROXY_MODE_MASK) == PROXY_MODE_RECV)
#define proxy_fails(pxy) (((pxy)->flags & PROXY_MODE_MASK) == PROXY_MODE_ERROR)
#define proxy_side_upstream(pxy) (((pxy)->flags & PROXY_SIDE_UPSTREAM) == PROXY_SIDE_UPSTREAM)
#define proxy_side_dnstream(pxy) (((pxy)->flags & PROXY_SIDE_UPSTREAM) != PROXY_SIDE_UPSTREAM)


/* The structure of a one-sided proxy, upstream & downstream.
 * These structures are indexed with the pollidx fields, which match
 * the values to the pollfd structures holding the file descriptors.
 * The peerdix fields couple two one-sided proxy into a bidirectional
 * proxy structure.
 *
 * Each proxy side toggles between reading the buffer and passing it on
 * to the other side.  This is done with one TLS record at a time.  The
 * proxy therefore is either in sending or receiving mode.  This has an
 * impact on the underlying file descriptors, but in a slightly complex
 * manner: Receiving is cleared by setting POLLIN on the same-index
 * pollfd structure as the proxy, but sending is cleared by setting
 * POLLOUT on the proxy's peeridx-indexed pollfd structure.  This means
 * that pollfd structures may actually have POLLIN and POLLOUT set at
 * the same time, in spite of the either-sending-or-receiving distinction
 * of each proxy side.
 *
 * Note that freeing pollfd structures may lead to some rearranging of
 * the pollidx and peeridx values, so no further state storage than in
 * these structures is possible, at least not acress pollfd_free() calls.
 *
 * Note that in initial and terminal stages, it is possible that peerdix
 * values are set to INVALID_POLLFD.
 */
struct proxy {
	struct mapping *proxymap;
	pollidx_t pollidx, peeridx;
	uint16_t flags;
	uint8_t rdbuf [MAXRECLEN];
	size_t read, written;
};


/********** FUNCTIONS **********/


/* Receive a TLS record or part of it from the proxy.
 * Updates the proxy to write state when complete.
 */
void recv_record (int sox, struct proxy *pxy);

/* Write a TLS record (or part of it) to the peering proxy.
 * Updates the proxy to read state when complete.
 */
void send_record (int sox, struct proxy *pxy);

/* Fetch the label contained in the first TLS record */
void record1_label (uint8_t *recbuf, size_t recbuflen, uint8_t **label, size_t *labellen);


