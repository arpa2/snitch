/* snitch/main.c -- Main program for the SNItch daemon.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>

#include "fun.h"


/* Linux specific bit; setting it to 0 makes code skip those sections */
#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif


/* Commandline parameters */
uint16_t setting_port = 4433;
struct in6_addr setting_addr = IN6ADDR_ANY_INIT;
char *setting_cfgfile = "/etc/snitch.conf";



/* Global variables */
bool interrupted = false;
struct pollfd *polls = NULL;
pollidx_t polls_used = 0;
pollidx_t polls_allocated = 0;
struct proxy *proxies = NULL;
pollidx_t proxies_allocated = 0;
#define proxies_used polls_used
//TODO// Read from configfiles
//TODO// Use hashing based on label
struct mapping map_cloud =  { NULL,        "cloud.vanrein.org", { { { 0x20,0x01,0x09,0x80,0x93,0xa5,0x00,0x01,0,0,0,0,0,0,0,0x43 } } }, 443 };
struct mapping map_krsd =   { &map_cloud,  "krsd.snitch", { { { 0x20,0x01,0x09,0x80,0x93,0xa5,0x00,0x01,0,0,0,0,0,0,0,0x43 } } }, 443 };
struct mapping map_kdctun = { &map_krsd,   "kdc.snitch",  IN6ADDR_LOOPBACK_INIT, 88 };
struct mapping map_sshtun = { &map_kdctun, "ssh.snitch",  IN6ADDR_LOOPBACK_INIT, 22 };
struct mapping map_https  = { &map_sshtun, "www.snitch",  IN6ADDR_LOOPBACK_INIT, 443 };



/* Allocate a polling entry; return INVALID_POLLIDX on failure. */
pollidx_t allocate_pollfd (int fd, short events) {
	if (polls_used == polls_allocated) {
		struct pollfd *newpolls = realloc (polls, (polls_allocated + 100) * sizeof (struct pollfd));
		if (!newpolls) {
			return INVALID_POLLIDX;
		}
		polls = newpolls;
		polls_allocated += 100;
	}
	polls [polls_used].fd = fd;
	polls [polls_used].events = events;
	polls [polls_used].revents = 0;
	return polls_used++;
}

/* Free a polling entry */
//TODO// Mark entries for garbage collection or reuse and skip renumbering?
void free_pollfd (pollidx_t idx) {
	int old;
	assert (idx <= polls_used);
	assert (idx != INVALID_POLLIDX);
	old = polls_used - 1;
	if (idx < old) {
		int ctr;
		memcpy (&polls [idx], &polls [old], sizeof (struct pollfd));
		for (ctr = 0; ctr < polls_used-1; ctr++) {
			if (proxies [ctr].pollidx == old) {
				proxies [ctr].pollidx = idx;
			}
			if (proxies [ctr].peeridx == old) {
				proxies [ctr].peeridx = idx;
			}
		}
	}
	polls_used--;
}

/* Allocate a proxy entry for a given pollidx_t value.  The idea is to call
 * this with the pollidx_t returned from allocate_pollfd(), and always call
 * this right afterwards to allocate control structures.
 * Each proxy structure reflects one side of the proxying relationship.
 * When this function fails, it returns -1 and otherwise it returns the
 * idx it got sent.  In case of error, you should not continue to rely on
 * the pollfd either, if your program assumes that they work together.
 */
int allocate_proxy (pollidx_t idx) {
	assert (idx <= polls_used);
	assert (idx != INVALID_POLLIDX);
	if (idx >= proxies_allocated) {
		struct proxy *newpxy = realloc (proxies, polls_allocated * sizeof (struct proxy));
		if (newpxy == NULL) {
			return -1;
		}
		proxies = newpxy;
		proxies_allocated = polls_allocated;
	}
	memset (proxies + idx, 0, sizeof (struct proxy));
	proxies [idx].pollidx = idx;	//TODO// Do we need this? It renumbers!
	proxies [idx].peeridx = INVALID_POLLIDX;
	return idx;
}

/* Free a proxy entry.  This currently does nothing, but the idea is to call
 * it sort of "in parallel" with free_pollfd, using the same idx to both but
 * not minding in what order they are called.
 */
void free_proxy (pollidx_t idx) {
	;
}

/* Portable function to set a socket into non-blocking mode.  This is a
 * requirement for asynchronous communication, especially for the accept()
 * function which could block if an attempted setup is torn down between
 * noticing the acticity on the socket and the invocation of accept().
 *
 * Source: http://www.kegel.com/dkftpbench/nonblocking.html
 * Credit: Bjorn Reese
 */
void socket_unblock (int sox) {
	int retval;
#ifdef O_NONBLOCK
	int flags;
	// Fix: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5.
	flags = fcntl (sox, F_GETFL, 0);
	if (flags == -1) {
		flags = 0;
		fprintf (stderr, "socket_unblock() may expose a bug on SunOS 4.1.x and AIX 3.2.5\n");
	}
	// We have O_NONBLOCK, so we use the Posix way to do it
	retval = fcntl (sox, F_SETFL, flags | O_NONBLOCK);
#else
	// In lieu of O_NONBLOCK, we use the old way of doing it
	flags = 1;
	retval = ioctl (sox, FIOBIO, &flags);
#endif
	if (retval == -1) {
		fprintf (stderr, "Failed to set socket %d to non-blocking mode.  Race conditions could occur!\n", sox);
	}
}


/* Accept a new incoming connection, which counts as the uplink.
 * While doing this, also ensure that a proxy structure has been allocated.
 * In case of failure, resolve matters internally and report vigorously.
 */
void accept_uplink (int sox) {
	int cnx;
	int pfd;
	cnx = accept (sox, NULL, 0);
	if (cnx == -1) {
		if ((errno != EWOULDBLOCK) && (errno != EAGAIN)) {
			perror ("Incoming connection refused");
		}
		return;
	}
	fprintf (stderr, "Accepted an incoming connection from upstream\n");
	pfd = allocate_pollfd (cnx, POLLIN | POLLPRI | POLLRDHUP | POLLERR | POLLHUP | POLLNVAL);
	if (pfd == INVALID_POLLIDX) {
		fprintf (stderr, "Failed to allocate pollfd for accepted connection\n");
		close (cnx);
	}
	if (allocate_proxy (pfd) != pfd) {
		fprintf (stderr, "Failed to allocate proxy for accepted connection");
		free_pollfd (pfd);
		close (cnx);
	}
	init_upstream_proxy (proxies + pfd);
	fprintf (stderr, "Successful accept_uplink () -- polls_used=%d, proxies_used=%d\n", polls_used, proxies_used);
}

/* Connect a client socket for a single connection.
 * Returns 0 for success, or -1 for failure (and sets errno).
 */
int connect_downlink (pollidx_t idx, uint8_t *label, size_t labellen) {
	int sox2;
	int idx2;
	struct mapping *map = &map_https;
	struct sockaddr_in6 sa;
	printf ("Connection has label %.*s\n", labellen, label);
	//
	// Lookup the map entry with this label
	//
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
	//
	// Assign the map to the existing upstream side
	//
	proxies [idx].proxymap = map;
	//
	// Connect to the downstream remote endpoint
	//
	printf ("Connecting service to downlink\n");
	sox2 = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox2 == -1) {
		return -1;
	}
	memset (&sa, 0, sizeof (sa));
	sa.sin6_family = AF_INET6;
	memcpy (&sa.sin6_addr, &map->fwdaddr, 16);
	sa.sin6_port = htons (map->fwdport);
	if (connect (sox2, (struct sockaddr *) &sa, sizeof (sa)) == -1) {
		close (sox2);
		return -1;
	}
	socket_unblock (sox2);
	fprintf (stderr, "Connected to downstream service for %.*s\n", labellen, label);
	//
	// Create the new pollfd and proxy structures
	//
	// Since this is a new connection, created because the first TLS record
	// is to be shipped there, it is setup with both the POLLIN flag and
	// POLLOUT flag set; POLLIN indicates that its own proxy side is ready
	// to receive data, POLLOUT indicates that the peer which finished
	// processing the first TLS record is in the mode to pass that on.
	//
	idx2 = allocate_pollfd (sox2, POLLOUT | POLLIN | POLLPRI | POLLRDHUP | POLLERR | POLLHUP | POLLNVAL);
	if (idx2 == INVALID_POLLIDX) {
		fprintf (stderr, "Closing down failing connections (no pollfd)\n");
		close (sox2);
		close (polls [idx].fd);
		free_pollfd (idx);
		return -1;
	}
	if (allocate_proxy (idx2) != idx2) {
		fprintf (stderr, "Closing down failing connections (no proxy)\n");
		close (sox2);
		close (polls [idx].fd);
		free_pollfd (idx2);
		free_pollfd (idx);
		return -1;
	}
	//
	// Setup proxymap, peeridx and flags values for this second side
	//
	proxies [idx2].proxymap = map;
	proxies [idx2].peeridx = idx ;
	proxies [idx ].peeridx = idx2;
	init_dnstream_proxy (proxies + idx2);
	fprintf (stderr, "Successful connect_downlink () -- polls_used=%d, proxies_used=%d\n", polls_used, proxies_used);
	return 0;
}

/* Shutdown one side of the proxy communication link. */
void shutdown_proxy (pollidx_t idx) {
	pollidx_t peeridx = proxies [idx].peeridx;
	if (peeridx != INVALID_POLLIDX) {
		proxies [peeridx].peeridx = INVALID_POLLIDX;
		shutdown_proxy (peeridx);
	}
	close (polls [idx].fd);
	free_pollfd (idx);
	free_proxy (idx);
	fprintf (stderr, "Successful shutdown_proxy () -- polls_used=%d, proxies_used=%d\n", polls_used, proxies_used);
}


/* The first TLS record is received over a proxy with an invalid peeridx.
 * When this arrives, scan for the label and use it to connect to the
 * other end of the requested connection, or set this one to error mode.
 * Return -1 on error, or 0 on success.
 */
int process_record1 (pollidx_t idx) {
	uint8_t *label = NULL;
	size_t labellen;
	bool error = true;
	assert (proxies [idx].peeridx == INVALID_POLLIDX);
	if (!proxy_sends (proxies + idx)) {
		return -1;
	}
	record_label (proxies [idx].rdbuf, proxies [idx].read, &label, &labellen);
	if (label) {
		if (connect_downlink (idx, label, labellen) != -1) {
			error = false;
		} else {
			perror ("Failure connecting downstream");
		}
	} else {
		printf ("DID NOT find a label, will shutdown upstream\n");
	}
	if (error) {
		set_proxymode (proxies + idx, PROXY_MODE_ERROR);
		return -1;
	} else {
		return 0;
	}
}

/* Daemon control loop */
void daemon (void) {
	while (poll (polls, polls_used, -1) > 0) {
		int idx;
		//
		// Process new incoming connections on the server socket
		//
		if (polls [0].revents & POLLIN) {
			accept_uplink (polls [0].fd);
			polls [0].revents &= ~POLLIN;
			// Continue general processing (for errors)
		}
		//
		// Iterate over sockets and process events
		//
		for (idx = 0; idx < polls_used; idx++) {
			//
			// Process errors, if any
			//
			if (polls [idx].revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
				shutdown_proxy (idx);
				polls [idx].revents &= ~ ( POLLIN | POLLOUT );
			}
			//
			// Process any incoming data
			//
			// This is not really complex; the proxy side and the
			// incoming file descriptor are found at the same
			// index.  So the pollfd's file descriptor and the
			// rdbuf, read, written values all reside in the
			// pollfd and proxies structures at idx.
			//
			if (polls [idx].revents & POLLIN) {
				recv_record (polls [idx].fd, proxies + idx);
				// Done receiving on this proxy side?
				if (!proxy_recvs (proxies + idx)) {
					polls [idx].events &= ~POLLIN;
					// Ended in error on this proxy side?
					if (!proxy_sends (proxies + idx)) {
						shutdown_proxy (idx);
					// ...or sending the first TLS record?
					} else if (proxies [idx].peeridx == INVALID_POLLIDX) {
						// Construct peer, with POLLOUT
						if (process_record1 (idx) == -1) {
							shutdown_proxy (idx);
						}
					// ...or sending a further TLS record?
					} else {
						// Setup sending in the peer
						polls [proxies [idx].peeridx].events |= POLLOUT;
					}
				}
			}
			//
			// Process any opportunity to send.
			//
			// POLLOUT is possible if the peer's proxy state is
			// currently sending (so, not receiving).  The data
			// (rdbuf, read, written) is found at the peer, and
			// the only thing found at the current index is the
			// POLLOUT event on this side's file descriptor.
			//
			if (polls [idx].revents & POLLOUT) {
				pollidx_t origin = proxies [idx].peeridx;
				send_record (polls [idx].fd, proxies + origin);
				// Done sending from the peer proxy side?
				if (!proxy_sends (proxies + origin)) {
					polls [idx].events &= ~POLLOUT;
					// Now receiving on the peer proxy side?
					if (proxy_recvs (proxies + origin)) {
						polls [origin].events |= POLLIN;
					// ...or did it end in error?
					} else {
						shutdown_proxy (origin);
					}
				}
			}
		}
	}
	//
	// Coming here, poll () must have been terminated by a signal
	//
	if (interrupted) {
		fprintf (stderr, "\nInterrupted\n");
	}
}

/* Cleanup by closing any open sockets */
void cleanup (void) {
	if (polls) {
		int idx;
		for (idx = polls_used-1; idx >= 0; idx--) {
			if (polls [idx].fd != -1) {
				close (polls [idx].fd);
			}
		}
		free (polls);
		polls = NULL;
	}
	if (proxies) {
		free (proxies);
		proxies = NULL;
	}
	fprintf (stderr, "Cleaned up sockets, freed memory for polls and proxies\n");
}

/* Interrupt the program to tear it down with grace */
void interrupt_program (int sig) {
	interrupted = true;
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
	socket_unblock (sox);
	memset (&sa, 0, sizeof (sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons (setting_port);
	memcpy (&sa.sin6_addr, &setting_addr, 16);
	if (bind (sox, (struct sockaddr *) &sa, sizeof (sa)) == -1) {
		perror ("Failed to bind socket");
		close (sox);
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Failed to listen to bound socket");
		close (sox);
		exit (1);
	}
	//
	// Setup first polling entry with accept() socket
	//
	if (allocate_pollfd (sox, POLLIN) != 0) {
		fprintf (stderr, "%s: Failure to initiate incoming polling structure\n");
		close (sox);
		exit (1);
	}
	if (allocate_proxy (0) != 0) {
		fprintf (stderr, "%s: Failure to initiate proxy structures\n");
		free (polls);
		polls = NULL;
		close (sox);
		exit (1);
	}
	//
	// Cleanup.
	//
	atexit (cleanup);
	//
	// Signals.
	//
	signal (SIGINT, interrupt_program);
	signal (SIGKILL, interrupt_program);
	signal (SIGABRT, interrupt_program);
	//
	// TODO: Daemon.
	//
	daemon ();
	//
	// Terminate.
	//
	exit (interrupted? 1: 0);
}
