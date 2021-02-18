
# nbd-client-relay

## Description
This allows arbitrary reconnection of NBD connections.

A kernel or client can attach to this relay and keep the connection open.
The relay will then attach to another nbd server and reconnect as needed
after disconnections.

## Building

```
# to make without tls
make nbd-client-relay-notls
# to make with gnu tls
make nbd-client-relay
```

## Usage
```
Usage: nbd-client-relay [-verbose] [-verifycert] [-debug] [-stdin]
[-write] [-rebuild] [-exportsize BYTESIZE] [-shorttimeout SECONDS]
[-longtimeout SECONDS] [-user USER] [-group GROUP] [-mount PATH]
[-certfile FILENAME] [-keyfile FILENAME] [URL] [-d] [BLOCKDEVICE]

URL can be of the form nbd://hostname:port/export,
nbd-tls://hostname:port/export, or file://fullpath
```

## Options

### -verbose
Currently not used

### -verifycert
Not yet implemented.

When in TLS mode, require the remote host to match its certificate, otherwise
refuse connection. If this is enabled and a certificate expires while a device
is mounted, the device won't remount until a new certificate is installed.

Default: disabled

### -debug
Run in foreground, allowing the program to print status messages.

Default: disabled

### -exportsize BYTESIZE

The linux kernel won't create a device until the size is known. Without
this setting, nbd-client-relay will wait until it can contact the remote
server before creating the device. Note that the "nbd-client-relay"
command will not complete until the device is set up. As such,
"nbd-client-relay nbd://myhost/myexport ; mount /dev/nbd0 /mnt/temp"
is fine but it might take a long time to return.

This option can be useful in the following situation: you'd like to immediately
create the nbd device _and_ the remote nbd server is unreachable. If the
exportsize is provided (via this option), then linux will allow the device to
be created immediately. Programs can now access the device at any time and
nbd-client-relay will attempt to reach the remote server after that
happens, as opposed to now. This also causes nbd-client-relay to return
immediately rather than blocking until the remote server is reached.

Default: disabled

### -shorttimeout SECONDS
This is the number of seconds to wait for transfers before remote connections
are considered broken. Slower networks should use higher values. Once a connection
times out, it will be re-attempted.

Default: 5

### -longtimeout SECONDS
This is the number of seconds to wait before killing idle connections. Since
connections will be reattempted on activity, this number can be fairly low to
reduce server resources.

Default: 600 (10 minutes)

### -user USER
This is the user to run as. The program _must_ be started with root permissions
to contact the kernel. Once that is accomplished, there's no practical need for
root permissions afterward. Reducing permissions is prudent for security.

Default: nobody

### -group GROUP
This is the group to run as. Reducing permissions is prudent for security.

Default: nogroup

### -certfile FILENAME
For TLS, this is the certfile in PEM format, likely named "yoursite.cert" or
similar. This is required for TLS.

Default: disabled

### -keyfile FILENAME
For TLS, this is the keyfile in PEM format, likely named "yoursite.key" or
similar. This is required for TLS.

Default: disabled

### -stdin
Read the URL from stdin (instead of the command line). The command line is
public to other users on the system. As such, private NBD exports should
be specified over stdin, which is not public.

It's possible to specify the beginning of the URL on the command line
and a suffix over stdin. This can be useful for psqfs-nbd-server's password
support (you can send "]password" over stdin).

Default: disabled

### DEVICE
The default value is /dev/nbd0 but adding another filename on the command
line will override this.

### URL
NBD and FILE urls are supported.

For NBD, URLs in the form "nbd://hostname:port/export" are used.
To enable TLS, use something like "nbd-tls://hostname:port/export" instead.
If ":port" is omitted, the default NBD port of 10809 is used.

To connect to a file in the filesystem, URLs of the form file://fullpath can
be used. For example, "file:///tmp/example.fs" or "file:///home/user/example.bin".
Full paths should be used. This has the effect of 3 '/' chars in the URL.
