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

#define PROXY_FLAG_RECV_UP	0x0001
#define PROXY_FLAG_SEND_UP	0x0002
#define PROXY_FLAG_RECV_DN	0x0004
#define PROXY_FLAG_SEND_DN	0x0008

#define PROXY_FLAG_ERROR	0x0010

#define PROXY_FLAGS_STREAM_UP	( PROXY_FLAG_RECV_UP | PROXY_FLAG_SEND_UP )
#define PROXY_FLAGS_STREAM_DN	( PROXY_FLAG_RECV_DN | PROXY_FLAG_SEND_DN )


/* The structure of a bidirectional proxy, upstream & downstream. */
struct proxy {
	struct mapping *proxymap;
	int upstream, dnstream;
	size_t upread, dnwritten;
	size_t dnread, upwritten;
	uint16_t flags;
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


