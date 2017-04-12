# OpenSSH on Fuchsia

## Server
OpenSSH's sshd is run by default at start-up. It's listening on IPv4 and IPv6. The username it expects is `fuchsia`.

An SSH key is generated at build time and included in `authorized-keys`. An `ssh_config` referencing that key is also
generated. The easiest way to ssh to your Fuchsia device named `foo-bar-baz-wib` is:
```
ssh -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config $(netaddr --fuchsia foo-bar-baz-wib)
```

Similarly you can `scp` or `sftp` using the same config file:
```
sftp -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config $(netaddr --fuchsia foo-bar-baz-wib)
scp -F $FUCHSIA_BUILD_DIR/ssh-keys/ssh_config \
  /local/path/file.txt \
  $(netaddr --fuchsia foo-bar-baz-wib):/remote/path/file.txt
```

*NOTE*: There remain some serious issues with the shell terminal handling. Escape characters in the prompt are printed
verbatim. Enter must be pressed twice to run a command.

## Client
The clients are built but don't work yet.
