#!/usr/bin/env python

import os
import shutil
import subprocess
import sys

key_types = ('dsa', 'ecdsa', 'ed25519', 'rsa')

def main(output_dir):
  # make sure the output directory exists
  if not os.path.exists(output_dir):
    os.makedirs(output_dir)

  for key_type in key_types:
    key_file = os.path.join(output_dir, 'ssh_host_%s_key' % key_type)
    if not os.path.exists(key_file):
      # generate new host key
      subprocess.check_call(['ssh-keygen', '-q', '-t', key_type, '-f', key_file, '-N', '', '-C', ''])

  authorized_keys = os.path.join(output_dir, 'authorized_keys')
  if not os.path.exists(authorized_keys):
    # pick the most recent ~/.ssh/*.pub that isn't ~/.ssh/*-cert.pub
    # this is what ssh-copy-id does
    dot_ssh = os.path.join(os.environ['HOME'], '.ssh')
    if not os.path.isdir(dot_ssh):
        sys.stderr.write('NOTE: ~/.ssh not found\n')
        open(authorized_keys, 'a').close()
        return

    files = [os.path.join(dot_ssh, f) for f in os.listdir(dot_ssh) if f.endswith('.pub') and not f.endswith('-cert.pub')]
    if len(files) == 0:
      sys.stderr.write('WARNING: No SSH public keys found in ~/.ssh\n')
      # create an empty authorized_keys file
      open(authorized_keys, 'a').close()
      return
    if len(files) > 1:
      files.sort(key=lambda f: os.path.getmtime(f))
    shutil.copyfile(files[-1], os.path.join(authorized_keys))


if __name__ == '__main__':
  assert len(sys.argv) == 2
  main(sys.argv[1])
