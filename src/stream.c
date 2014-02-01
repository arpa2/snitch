/* snitch/stream.c -- Read and write parts of the TLS stream.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <unistd.h>

#include "fun.h"


/* Read a record from the stream. */
void fetch_record (int cnx, uint8_t **buf, size_t *buflen) {
	size_t minlen = 5;
	size_t gotlen = 0;
	size_t rdlen = 1;
	*buflen = 0;
	*buf = malloc (5 + 16384);
	if (!*buf) {
		perror ("No room for record buffer");
		return;
	}
	do {
		if (rdlen == 0) {
			fprintf (stderr, "Connection terminated unexpectedly\n");
			free (*buf);
			*buf = NULL;
			return;
		}
		rdlen = read (cnx, *buf + gotlen, minlen - gotlen);
		if (rdlen == -1) {
			perror ("Receiving failure");
			free (*buf);
			*buf = NULL;
			return;
		}
		gotlen += rdlen;
		if ((minlen == 5) && (gotlen >= 5)) {
			minlen += (((size_t) (*buf) [3]) << 8) |
				  (((size_t) (*buf) [4])     );
		}
	} while (gotlen < minlen);
	*buflen = gotlen;
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

