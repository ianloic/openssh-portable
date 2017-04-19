# OpenSSH on Fuchsia

## Server

OpenSSH's sshd is run by default at start-up. It's listening on IPv4 and IPv6.
The username it expects is `fuchsia`.

An SSH key is generated at build time and included in `authorized-keys`. An
`ssh_config` referencing that key is also generated. The easiest way to ssh to
your default Fuchsia device is:

```
ssh -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config \
  $($FUCHSIA_OUT_DIR/build-magenta/tools/netaddr --fuchsia)
```

Similarly you can `scp` or `sftp` using the same config file. Note that
scp and sftp require the ipv6 address to be in square brackets, unlike ssh.

```
sftp -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config \
  [$($FUCHSIA_OUT_DIR/build-magenta/tools/netaddr --fuchsia)]

scp -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config \
  /local/path/file.txt \
  [$($FUCHSIA_OUT_DIR/build-magenta/tools/netaddr --fuchsia)]:/remote/path
```

*NOTE 1*: Transfers of large files will stall and eventually fail. The cause is
being investigated.

*NOTE 2*: There remain some serious issues with the shell terminal handling.
Escape characters in the prompt are printed verbatim. Enter must be pressed
twice to run a command.

## Client

The clients are built but don't work yet.
