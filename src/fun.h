/* snitch/fun.h -- Structures and function prototypes
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


/********** STRUCTURES **********/


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

#define set_upstream_proxymode(pxy,m) (((pxy)->upflags = ((pxy)->upflags & ~PROXY_MODE_MASK) | (m)))
#define set_dnstream_proxymode(pxy,m) (((pxy)->dnflags = ((pxy)->dnflags & ~PROXY_MODE_MASK) | (m)))

#define init_dnstream_proxy(pxy) { (pxy)->upflags = PROXY_MODE_RECV; }
#define init_upstream_proxy(pxy) { (pxy)->upflags = PROXY_MODE_RECV; }

#define proxy_sends_upstream(pxy) (((pxy)->upflags & PROXY_MODE_MASK) == PROXY_MODE_SEND)
#define proxy_recvs_upstream(pxy) (((pxy)->upflags & PROXY_MODE_MASK) == PROXY_MODE_RECV)
#define proxy_sends_dnstream(pxy) (((pxy)->dnflags & PROXY_MODE_MASK) == PROXY_MODE_SEND)
#define proxy_recvs_dnstream(pxy) (((pxy)->dnflags & PROXY_MODE_MASK) == PROXY_MODE_RECV)


/* The structure of a bidirectional proxy, upstream & downstream. */
struct proxy {
	struct mapping *proxymap;
	int upstream, dnstream;
	size_t upread, dnwritten;
	size_t dnread, upwritten;
	uint16_t upflags, dnflags;
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


