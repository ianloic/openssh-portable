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

Run `sshd` with `-d` for debug mode and `-r` to disable reexecing:
```
$ sshd -dr
```
### scp

### sftp

## Port Notes

TODO
