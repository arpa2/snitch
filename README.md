# SNItch -- the SNI-based Switch

> *This tool switches incoming TLS-connections based on the SNI contained in
> them.  It is assumed that the full SNI extension fits in the first record
> transmitted.*


## Commandline Parameters

The SNItch is made to listen to an address and port, which default to any
address and port number 443, respectively.  Use `-l` to override the address
and `-p` to override the port.  Addresses are interpreted as IPv6 addresses,
but you may place `::` in front of an IPv4 address if you like.

The configuration file is assumed to live at /etc/snitch.conf and if not,
the `-c` option can be used to introduce another filename.


## Configuration

The configuration file the explains how forwarding takes place.  Any line
that does not start with whitespace or a `#` character must be of the
following format:

	label inthost intport [flags...]

Each of the phrases is separated by whitespace.  Trailing whitespace is
optional, and will be ignored.  So, it is okay to end a line immediately
after the port number.  It is not acceptable to start a configuration
line with whitespace.  None of the terms mentioned above may contain a
space, and with the exception of [flags...] none of them is empty.

The `label` is the name used in SNI.  It may be a DNS-published name, or
something internal if both ends see fit to using that.

The `inthost` is an IPv6 address of an internal host.  Once again, prefix
IPv4 addresses with :: if you have a nostalgic mood.

The `intport` is a port number to connect to.

The optional `[flags...]` are whitespace-separate words that detail what
needs to be done with the traffic while in transit.  For now, there are
no flags defined.

