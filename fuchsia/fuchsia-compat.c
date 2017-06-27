// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <launchpad/launchpad.h>
#include <magenta/syscalls.h>
#include <mxio/io.h>
#include <pthread.h>
#include <pwd.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "openbsd-compat/bsd-misc.h"
#include "misc.h"

int chroot(const char* path) { return -1; }

typedef struct Authctxt Authctxt;

int sys_auth_passwd(Authctxt* authctxt, const char* password) {
  // Password authentication always fails.
  return 0;
}

struct passwd* getpwent(void) {
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

struct passwd* getpwnam(const char* name) {
  return getpwent();
}

struct passwd* getpwuid(uid_t uid) {
  return getpwent();
}

#define ARGV_MAX 256

typedef struct {
  enum { UNUSED, RUNNING, STOPPED } state;
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
  for (int i = 0; i < NUM_CHILDREN; i++) {
    if (children[i].state == UNUSED) {
      return i + BASE_PID;
    }
  }
  fprintf(stderr, "Can't allocate new pid.\n");
  exit(1);
}

static volatile mysig_t sigchld_handler = SIG_IGN;

static void* wait_thread_func(void* voidp) {
  Child* child = voidp;

  mx_signals_t observed;
  mx_object_wait_one(child->handle, MX_PROCESS_TERMINATED, MX_TIME_INFINITE, &observed);

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

// Write to a non-blocking fd, blocking until writing has completed or an error has occurred.
static bool blocking_write(int fd, const char* buffer, size_t length) {
  uint32_t events;
  size_t offset = 0;
  while (offset < length) {
    if (mxio_wait_fd(fd, MXIO_EVT_WRITABLE, &events, MX_TIME_INFINITE) < 0) {
      // Wait failed.
      return false;
    }
    ssize_t length_written = write(fd, buffer + offset, length - offset);
    if (length_written <= 0) {
      // EOF or error.
      return false;
    }
    offset += length_written;
  }
  return true;
}

// A thread that processes output.
// Currently just nothing but shuffle bytes.
static void* process_input_thread_func(void* voidp) {
  int* fds = voidp;
  char buf[128];

  for (;;) {
    uint32_t events;
    if (mxio_wait_fd(fds[0], MXIO_EVT_READABLE, &events, MX_TIME_INFINITE) < 0) {
      // Wait failed.
      break;
    }
    int length = read(fds[0], buf, sizeof(buf));
    if (length <= 0) {
      // EOF or error.
      break;
    }
    if (!blocking_write(fds[1], buf, length)) {
      break;
    }
  }

  close(fds[0]);
  close(fds[1]);

  free(fds);

  return NULL;
}

// Start an input processing thread that reads from fd.
// The returned fd will receive the processed input.
static int run_input_processing_thread(int fd) {
  int pip[2];
  if (pipe(pip) < 0) {
    fprintf(stderr, "Error creating pipe: %s\n", strerror(errno));
    return -1;
  }

  set_nonblock(pip[0]);
  set_nonblock(pip[1]);

  // Allocate the structure to send the fds to the thread.
  int* fds = malloc(2 * sizeof(int));
  if (!fds) {
    fprintf(stderr, "Malloc failed.\n");
    return -1;
  }
  fds[0] = fd;
  fds[1] = pip[1];

  // Start the thread.
  pthread_t processing_thread;
  if (pthread_create(&processing_thread, NULL, process_input_thread_func, fds) != 0) {
    fprintf(stderr, "Failed to create input processing thread for %d: %s\n", fd, strerror(errno));
    return -1;
  }

  return pip[0];
}

// A thread that processes output.
// Currently just does \n -> \r\n translation.
static void* process_output_thread_func(void* voidp) {
  int* fds = voidp;
  char buf[128];

  for (;;) {
    uint32_t events;
    if (mxio_wait_fd(fds[0], MXIO_EVT_READABLE, &events, MX_TIME_INFINITE) < 0) {
      // Wait failed.
      break;
    }
    int length = read(fds[0], buf, sizeof(buf));
    if (length <= 0) {
      // EOF or error.
      break;
    }
    char* p = buf;
    while (length > 0) {
      char* lf = memchr(p, '\n', length);
      if (lf == NULL) {
        // No \n found.
        if (!blocking_write(fds[1], p, length)) {
          goto out_end;
        }
        break;
      } else {
        // \n found at lf.
        if (lf != p) {
          // There are some bytes to print there first.
          if (!blocking_write(fds[1], p, lf - p)) {
            goto out_end;
          }
        }
        // Send \r\n.
        const char* crlf = "\r\n";
        if (!blocking_write(fds[1], crlf, 2)) {
          goto out_end;
        }
        // Skip over the \n and what came before it.
        length -= (lf - p) + 1;
        p = lf + 1;
      }
    }
  }
out_end:

  close(fds[0]);
  close(fds[1]);

  free(fds);

  return NULL;
}

// Start an output processing thread that reads from fd.
// The returned fd will receive the processed output.
static int run_output_processing_thread(int fd) {
  // Create a pipe to return processed bytes.
  int pip[2];
  if (pipe(pip) < 0) {
    fprintf(stderr, "Error creating pipe: %s\n", strerror(errno));
    return -1;
  }

  set_nonblock(pip[0]);
  set_nonblock(pip[1]);

  // Allocate the structure to send the fds to the thread.
  int* fds = malloc(2 * sizeof(int));
  if (!fds) {
    fprintf(stderr, "Malloc failed.\n");
    return -1;
  }
  fds[0] = pip[0];
  fds[1] = fd;

  // Start the thread.
  pthread_t processing_thread;
  if (pthread_create(&processing_thread, NULL, process_output_thread_func, fds) != 0) {
    fprintf(stderr, "Failed to create output processing thread for %d: %s\n", fd, strerror(errno));
    return -1;
  }

  return pip[1];
}

pid_t fuchsia_launch_child(const char* command, int in, int out, int err, bool transform) {
  const char* argv[ARGV_MAX];
  int argc = 1;
  argv[0] = "/boot/bin/sh";
  if (command) {
    argv[argc++] = "-c";
    argv[argc++] = command;
  } else {
    command = argv[0];
  }
  argv[argc] = NULL;

  if (transform) {
    in = run_input_processing_thread(in);
    bool same = (out == err);
    out = run_output_processing_thread(out);
    if (same) {
      err = out;
    } else {
      err = run_output_processing_thread(err);
    }
  }

  launchpad_t* lp;
  launchpad_create(0, command, &lp);
  launchpad_load_from_file(lp, argv[0]);
  launchpad_set_args(lp, argc, argv);
  launchpad_clone(lp, LP_CLONE_MXIO_NAMESPACE | LP_CLONE_MXIO_CWD);
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
    fprintf(stderr, " status=%d\n", launchpad_get_status(lp));
    exit(1);
  }

  pid_t pid = get_unused_pid();
  Child* child = get_child(pid);
  child->state = RUNNING;
  child->handle = proc;

  pthread_t wait_thread;
  if (pthread_create(&wait_thread, NULL, wait_thread_func, (void*)child) != 0) {
    fprintf(stderr, "Failed to create process waiter thread: %s\n", strerror(errno));
    exit(1);
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
