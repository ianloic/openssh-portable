// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <launchpad/launchpad.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int chroot(const char *path) { return -1; }

typedef struct Authctxt Authctxt;

int sys_auth_passwd(Authctxt *authctxt, const char *password) {
  // Password authentication always fails.
  return 0;
}

struct passwd *getpwent(void) {
  static struct passwd static_passwd = {
      .pw_name = "fuchsia",
      .pw_passwd = "",
      .pw_uid = 23,  // matches MX_UID
      .pw_gid = 23,
      .pw_gecos = "Fuchsia",
      .pw_dir = "/",
      .pw_shell = "/boot/bin/sh",
  };

  return &static_passwd;
}

struct passwd *getpwnam(const char *name) {
  return getpwent();
}

struct passwd *getpwuid(uid_t uid) {
  return getpwent();
}

#define ARGV_MAX 256

mx_handle_t fuchsia_launch_child(const char *command, int in, int out, int err) {
  const char *argv[ARGV_MAX];
  int argc = 1;
  argv[0] = "/boot/bin/sh";
  if (command) {
    argv[argc++] = "-c";
    argv[argc++] = command;
  } else {
    command = argv[0];
  }
  argv[argc] = NULL;

  launchpad_t *lp;
  launchpad_create(0, command, &lp);
  launchpad_load_from_file(lp, argv[0]);
  launchpad_set_args(lp, argc, argv);
  launchpad_clone(lp, LP_CLONE_MXIO_ROOT|LP_CLONE_MXIO_CWD);
  // TODO: set up environment
  launchpad_transfer_fd(lp, in, STDIN_FILENO);
  launchpad_transfer_fd(lp, out, STDOUT_FILENO);
  launchpad_transfer_fd(lp, err, STDERR_FILENO);

  mx_handle_t proc = 0;
  const char* errmsg;

  mx_status_t status = launchpad_go(lp, &proc, &errmsg);
  if (status < 0) {
    printf("error from launchpad_go: %s\n", errmsg);
  }

  return proc;
}
