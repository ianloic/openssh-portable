// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <launchpad/launchpad.h>
#include <magenta/syscalls.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "openbsd-compat/bsd-misc.h"

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

typedef struct {
  enum {
    UNUSED, RUNNING, STOPPED
  } state;
  mx_handle_t handle;
  int exit_code;
} Child;

#define BASE_PID 2
#define NUM_CHILDREN 256
static Child children[NUM_CHILDREN];

static Child* get_child(pid_t pid) {
  assert(pid - BASE_PID < NUM_CHILDREN);
  assert(pid >= BASE_PID);
  return &children[pid - BASE_PID];
}

static pid_t get_unused_pid() {
  for (int i=0; i<NUM_CHILDREN; i++) {
    if (children[i].state == UNUSED) {
      return i+BASE_PID;
    }
  }
  fprintf(stderr, "Can't allocate new pid.\n");
  exit(1);
}

static volatile mysig_t sigchld_handler = SIG_IGN;

static void* wait_thread_func(void* voidp) {
  Child* child = voidp;

  mx_signals_t observed;
  mx_object_wait_one(child->handle, MX_PROCESS_SIGNALED, MX_TIME_INFINITE, &observed);

  mx_info_process_t info;
  size_t actual;
  mx_object_get_info(child->handle, MX_INFO_PROCESS, &info, sizeof(info), &actual, NULL);

  child->state = STOPPED;
  child->exit_code = info.return_code;

  mysig_t handler = sigchld_handler;
  if (handler == SIG_IGN || handler == SIG_DFL) {
    // Don't call a handler
  } else {
    handler(SIGCHLD);
  }

  return NULL;
}

pid_t fuchsia_launch_child(const char *command, int in, int out, int err) {
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
  if (in == out) {
    launchpad_clone_fd(lp, in, STDIN_FILENO);
  } else {
    launchpad_transfer_fd(lp, in, STDIN_FILENO);
  }
  if (out == err) {
    launchpad_clone_fd(lp, out, STDOUT_FILENO);
  } else {
    launchpad_transfer_fd(lp, out, STDOUT_FILENO);
  }
  launchpad_transfer_fd(lp, err, STDERR_FILENO);

  mx_handle_t proc = 0;
  const char* errmsg;

  mx_status_t status = launchpad_go(lp, &proc, &errmsg);
  if (status < 0) {
    fprintf(stderr, "error from launchpad_go: %s\n", errmsg);
    exit(1);
  }

  pid_t pid = get_unused_pid();
  Child* child = get_child(pid);
  child->state = RUNNING;
  child->handle = proc;

  pthread_t wait_thread;
  if (pthread_create(&wait_thread, NULL, wait_thread_func, (void*)child) != 0) {
    fprintf(stderr, "Failed to create process waiter thread: %s\n", strerror(errno));
  }

  return pid;
}

mysig_t mysignal(int signum, mysig_t handler) {
  if (signum == SIGCHLD) {
    sigchld_handler = handler;
  }
  // Ignore all non-SIGCHLD requests
  return handler;
}

pid_t waitpid(pid_t pid, int* status, int options) {
  if (pid == -1 || pid == 0) {
    // Find an exited process.
    for (pid = BASE_PID; pid < BASE_PID + NUM_CHILDREN; pid++) {
      if (get_child(pid)->state == STOPPED) {
        return waitpid(pid, status, options);
      }
    }
    if (options & WNOHANG) {
      return 0;
    } else {
      fprintf(stderr, "No child pids waiting for wait.\n");
      exit(1);
    }
  }

  Child* child = get_child(pid);
  if (child->state != STOPPED) {
    fprintf(stderr, "Child with pid %d isn't stopped.\n", pid);
    exit(1);
  }

  if (status) {
    *status = child->exit_code;
  }
  child->state = UNUSED;

  return pid;
}
