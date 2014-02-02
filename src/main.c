/* snitch/main.c -- Main program for SNItch.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <netinet/in.h>

#include "fun.h"


/* Commandline parameters */
uint16_t setting_port = 4433;
struct in6_addr setting_addr = IN6ADDR_ANY_INIT;
char *setting_cfgfile = "/etc/snitch.conf";



/* Mapping structures */
//TODO// Read from configfiles
//TODO// Use hashing based on label
struct mapping map_kdctun = { NULL,        "kdc.snitch", IN6ADDR_LOOPBACK_INIT, 88 };
struct mapping map_sshtun = { &map_kdctun, "ssh.snitch", IN6ADDR_LOOPBACK_INIT, 22 };
struct mapping map_https  = { &map_sshtun, "www.snitch", IN6ADDR_LOOPBACK_INIT, 443 };


/* Connect a client socket for a single connection.
 * Returns 0 for success, or -1 for failure (and sets errno).
 */
int connect_downlink (struct proxy *pxy, uint8_t *label, size_t labellen) {
	struct mapping *map = &map_https;
	struct sockaddr_in6 sa;
	printf ("Connection has label %.*s\n", labellen, label);
	while (map) {
		if ((memcmp (map->label, label, labellen) == 0) && (map->label [labellen] == 0)) {
			break;
		}
		map = map->next;
	}
	if (!map) {
		errno = ENOKEY;
		return -1;
	}
	pxy->proxymap = map;
	printf ("Connecting service to downlink\n");
	pxy->dnstream = socket (AF_INET6, SOCK_STREAM, 0);
	if (pxy->dnstream == -1) {
		return -1;
	}
	memset (&sa, 0, sizeof (sa));
	sa.sin6_family = AF_INET6;
	memcpy (&sa.sin6_addr, &map->fwdaddr, 16);
	sa.sin6_port = htons (map->fwdport);
	if (connect (pxy->dnstream, (struct sockaddr *) &sa, sizeof (sa)) == -1) {
		close (pxy->dnstream);
		pxy->dnstream = -1;
		return -1;
	}
	return 0;
}

/* Daemon control loop */
int daemon (int sox) {
	int cnx;
	while (cnx = accept (sox, NULL, 0), cnx != -1) {
		uint8_t *label;
		size_t labellen;
		struct proxy *pxy = malloc (sizeof (*pxy));
		printf ("Accepted new connection from upstream\n");
		if (!pxy) {
			perror ("Could not allocate proxy buffer");
			close (cnx);
			continue;
		}
		pxy->upstream = cnx;
		pxy->dnstream = -1;
		pxy->upread = pxy->dnwritten = pxy->dnread = pxy->upwritten = 0;
		pxy->flags = PROXY_FLAG_RECV_DN;
		//TODO// Synchronous read; moving towards poll()
		while (pxy->flags & PROXY_FLAG_RECV_DN) {
			recv_downstream (pxy);
			printf ("Received %d bytes total downstream\n", pxy->dnread);
		}
		if (pxy->flags & PROXY_FLAG_SEND_DN) {
			printf ("Ready to send bytes downstream\n");
		} else {
			printf ("NOT ready to send bytes downstream\n");
		}
		record_label (pxy->dnbuf, pxy->dnread, &label, &labellen);
		if (label) {
			if (connect_downlink (pxy, label, labellen) != -1) {
				pxy->flags |= PROXY_FLAG_RECV_UP;
				//TODO// Sync write; moving towards poll()
				while (pxy->flags & PROXY_FLAG_SEND_DN) {
					send_downstream (pxy);
					printf ("Sent %d bytes total downstream\n", pxy->dnwritten);
				}
				close (pxy->dnstream);
			} else {
				perror ("Failure connecting downstream");
			}
		} else {
			printf ("DID NOT find a label\n");
		}
		close (pxy->upstream);
		free (pxy);
	}
}

/* Main program */
int main (int argc, char *argv []) {
	//
	// Variables.
	//
	int sox;
	FILE *cfg;
	struct sockaddr_in6 sa;
	//
	// Commandline.
	//
	if (argc > 1) {
		fprintf (stderr, "%s: TODO: Commandline parameters are not currently processed.\nDefaults are: -l :: -p 443 -c /etc/snitch.conf\n", argv [0]);
		exit (1);
	}
	cfg = fopen (setting_cfgfile, "r");
	if (!cfg) {
		fprintf (stderr, "%s: Failed to open configuration file\n", argv [0]);
		exit (1);
	} else {
		fprintf (stderr, "%s: TODO: Ignoring configuration file %s\n", argv [0], setting_cfgfile);
	}
	//TODO// Process lines... instead of static mapping
	fclose (cfg);
	//
	// Socket.
	//
	sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox == -1) {
		perror ("Failed to allocate a server socket");
		exit (1);
	}
	memset (&sa, 0, sizeof (sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons (setting_port);
	memcpy (&sa.sin6_addr, &setting_addr, 16);
	if (bind (sox, (struct sockaddr *) &sa, sizeof (sa)) == -1) {
		perror ("Failed to bind socket");
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Failed to listen to bound socket");
		exit (1);
	}
	//
	// TODO: Daemon.
	//
	daemon (sox);
	//
	// Cleanup.
	//
	close (sox);
}
