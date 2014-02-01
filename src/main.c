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

#include <netinet/in.h>

#include "fun.h"


/* Structures to store mappings */
struct mapping {
	struct mapping *next;
	char *label;
	struct in6_addr fwdaddr;
	uint16_t fwdport;
};


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


/* Service for a single connection */
void service (int sox, uint8_t *label, size_t labellen) {
	struct mapping *map = &map_https;
	printf ("Connection has label %.*s\n", labellen, label);
	while (map) {
		if ((memcmp (map->label, label, labellen) == 0) && (map->label [labellen] == 0)) {
			break;
		}
		map = map->next;
	}
	if (!map) {
		return;
	}
	printf ("Relaying service to remote\n");
}

/* Daemon control loop */
int daemon (int sox) {
	int cnx;
	while (cnx = accept (sox, NULL, 0), cnx != -1) {
		uint8_t *buf;
		size_t buflen;
		uint8_t *label;
		size_t labellen;
		fetch_record (cnx, &buf, &buflen);
		if (buf) {
			record_label (buf, buflen, &label, &labellen);
			if (label) {
				service (cnx, label, labellen);
			}
		}
		close (cnx);
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
		perror ("Failed to allocate a network socket");
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
