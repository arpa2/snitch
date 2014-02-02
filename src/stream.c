/* snitch/stream.c -- Read and write parts of the TLS stream.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "fun.h"


/* Receive a (partial) record from the stream.
 * Returns 1 when a record is fully loaded, 0 for more to do, -1 for error.
 */
static int recv_partial_record (int cnx, uint8_t *buf, size_t *sofar) {
	size_t minlen = 5;
	size_t didlen = *sofar;
	size_t iolen;
	printf ("Receiving minlen = %d, didlen = %d, iolen = ???\n", minlen, didlen);
	if (didlen >= 5) {
		minlen += (((size_t) buf [3]) << 8) |
			  (((size_t) buf [4])     );
	}
	printf ("receiving minlen = %d, didlen = %d, iolen = ???\n", minlen, didlen);
	iolen = read (cnx, buf + didlen, minlen - didlen);
	printf ("receiving minlen = %d, didlen = %d, iolen = %d\n", minlen, didlen, iolen);
	if (iolen == -1) {
		if ((errno == EWOULDBLOCK) && (errno == EAGAIN)) {
			return 0;
		}
		perror ("Communication failure");
		*sofar = 0;
		return -1;
	}
	*sofar = didlen += iolen;
	printf ("receiving minlen = %d, didlen = %d, iolen = %d\n", minlen, didlen, iolen);
	if (didlen >= minlen) {
		return (minlen > 5);
	}
	if (iolen == 0) {
		fprintf (stderr, "Connection terminated unexpectedly\n");
		return -1;
	}
	return 0;
}

/* Send a (partial) record from the stream.
 * Returns 1 when a record is fully loaded, 0 for more to do, -1 for error.
 */
static int send_partial_record (int cnx, uint8_t *buf, size_t *sofar, size_t sndlen) {
	size_t didlen = *sofar;
	size_t iolen;
	printf ("Sending sndlen = %d, didlen = %d, iolen = ???\n", sndlen, didlen);
	iolen = write (cnx, buf + didlen, sndlen - didlen);
	printf ("sending sndlen = %d, didlen = %d, iolen = %d\n", sndlen, didlen, iolen);
	if (iolen == -1) {
		if ((errno == EWOULDBLOCK) && (errno == EAGAIN)) {
			return 0;
		}
		perror ("Communication failure");
		*sofar = 0;
		return -1;
	}
	*sofar = didlen += iolen;
	printf ("sending sndlen = %d, didlen = %d, iolen = %d\n", sndlen, didlen, iolen);
	if (didlen >= sndlen) {
		return 1;
	}
	if (iolen == 0) {
		fprintf (stderr, "Connection terminated unexpectedly\n");
		return -1;
	}
	return 0;
}


/* Receive a TLS record or part of it from the proxy.
 * Updates the proxy to write state when complete.
 */
void recv_record (int sox, struct proxy *pxy) {
	switch (recv_partial_record (sox, pxy->rdbuf, &pxy->read)) {
	case 1:
		set_proxymode (pxy, PROXY_MODE_SEND);
		pxy->written = 0;
		break;
	case -1:
		set_proxymode (pxy, PROXY_MODE_ERROR);
		break;
	default:
		break;
	}
}


/* Write a TLS record (or part of it) to the peering proxy.
 * Updates the proxy to read state when complete.
 */
void send_record (int sox, struct proxy *pxy) {
	switch (send_partial_record (sox, pxy->rdbuf, &pxy->written, pxy->read)) {
	case 1:
		set_proxymode (pxy, PROXY_MODE_RECV);
		pxy->read = pxy->written = 0;
		break;
	case -1:
		set_proxymode (pxy, PROXY_MODE_ERROR);
		break;
	default:
		break;
	}
}


/* Fetch the label contained in a record */
void record_label (uint8_t *recbuf, size_t recbuflen, uint8_t **label, size_t *labellen) {
	size_t pos = 5 + 1;	// Past record header and handshake type
	size_t skiplen;
	*label = NULL;
	*labellen = 0;
	//
	// Maximise record to at most the client handshake
	//
	if (pos + 3 > recbuflen) {
		return;
	}
	skiplen = (((size_t) recbuf [pos + 0]) << 16) |
		  (((size_t) recbuf [pos + 1]) <<  8) |
		  (((size_t) recbuf [pos + 2])      );
printf ("Client handshake length = %d\n", skiplen);
	if (pos + 3 + skiplen < recbuflen) {
		recbuflen = pos + 3 + skiplen;
	}
	pos += 3;
	//
	// Skip the version and random material
	//
	if (pos + 2 + 32 > recbuflen) {
		return;
	}
	pos += 2 + 32;
	//
	// Skip the session ID
	//
	if (pos + 1 > recbuflen) {
		return;
	}
	skiplen = recbuf [pos];
printf ("Session ID length = %d\n", skiplen);
	pos += 1 + skiplen;
	//
	// Skip the cipher suites
	//
	if (pos + 2 > recbuflen) {
		return;
	}
	skiplen = (((size_t) recbuf [pos + 0]) << 8) |
		  (((size_t) recbuf [pos + 1])     );
printf ("Cipher suites length = %d\n", skiplen);
	pos += 2 + skiplen;
	//
	// Skip the compression methods
	//
	if (pos + 1 > recbuflen) {
		return;
	}
	skiplen = recbuf [pos];
printf ("Compression methods length = %d\n", skiplen);
	pos += 1 + skiplen;
	//
	// Dive into the extensions
	// Note: Assume that the SNI extension is in the first record
	//
	if (pos + 2 > recbuflen) {
		return;
	}
	skiplen = (((size_t) recbuf [pos + 0]) << 8) |
		  (((size_t) recbuf [pos + 1])     );
printf ("Extensions total length = %d\n", skiplen);
	if (pos + 2 + skiplen < recbuflen) {
		recbuflen = pos + 2 + skiplen;
	}
	pos += 2;
	//
	// Iterate extensions until SNI comes up
	//
	while (pos + 4 <= recbuflen) {
		skiplen = (((size_t) recbuf [pos + 2]) << 8) |
			  (((size_t) recbuf [pos + 3])     );
printf ("Extension length = %d\n", skiplen);
		if (pos + 4 + skiplen > recbuflen) {
			return;
		}
		if ((recbuf [pos + 0] == 0x00) || (recbuf [pos + 1] == 0x00)) {
			//TODO// Dive into the Server Name structure
			*label = &recbuf [pos + 4 + 5];
			*labellen = skiplen - 5;
			return;
		}
		pos = pos + 4 + skiplen;
	}
	//
	// Report that nothing was found
	//
	return;
}

