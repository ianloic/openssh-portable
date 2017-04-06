# OpenSSH on Fuchsia

## Running

### ssh

### sshd

First generate host keys on your Fuchsia device:
```
$ ssh-keygen -A
```

Then copy your public SSH key to your Fuchsia device from your host:
```
% netcp ~/.ssh/id_rsa.pub :/.ssh/authorized_keys
```

Under `listen` run `sshd -ire` where `i` is for inetd mode, `r` to disable
reexecing and `e` to print logs to stderr:
```
$ listen 22 /system/bin/sshd -ire
```
### scp

### sftp

## Port Notes

TODO
