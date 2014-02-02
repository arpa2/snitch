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
#define proxy_side_upstream(pxy) (((pxy)->flags & PROXY_SIDE_UPSTREAM) == PROXY_SIDE_UPSTREAM)
#define proxy_side_dnstream(pxy) (((pxy)->flags & PROXY_SIDE_UPSTREAM) != PROXY_SIDE_UPSTREAM)


/* The structure of a one-sided proxy, upstream & downstream.
 * These structures are indexed with the pollidx fields, which match
 * the values to the pollfd structures holding the file descriptors.
 * The peerdix fields couple two one-sided proxy into a bidirectional
 * proxy structure.
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
	//TODO:DEPRECATE:BIDIRSETTINGS//
	int upstream, dnstream;
	size_t upread, dnwritten;
	size_t dnread, upwritten;
	uint8_t upbuf [MAXRECLEN], dnbuf [MAXRECLEN];
};


/********** FUNCTIONS **********/


/* Read a (partial) record in the downstream direction.
 * Updates the proxy's flags to set future reading or writing.
 */
void recv_downstream (struct proxy *pxy);

/* Read a (partial) record in the upstream direction.
 * Updates the proxy's flags to set future reading or writing.
 */
void recv_upstream (struct proxy *pxy);

/* Write a (partial) record in the downstream direction.
 * Returns 1 when a record has been fully sent, 0 otherwise.
 */
int send_downstream (struct proxy *pxy);

/* Write a (partial) record in the upstream direction.
 * Returns 1 when a record has been fully sent, 0 otherwise.
 */
int send_upstream (struct proxy *pxy);


/* Fetch the label contained in a record */
void record_label (uint8_t *recbuf, size_t recbuflen, uint8_t **label, size_t *labellen);


