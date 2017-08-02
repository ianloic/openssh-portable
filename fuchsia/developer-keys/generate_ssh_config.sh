#!/bin/sh
cat <<EOF > $2
Host *
  CheckHostIP no
  StrictHostKeyChecking no
  ForwardAgent no
  ForwardX11 no
  GSSAPIDelegateCredentials no
  UserKnownHostsFile /dev/null
  User fuchsia
  IdentityFile $1
  ControlPersist yes
  ControlMaster auto
  ControlPath /tmp/fuchsia-$USER-%r@%h:%p
EOF
