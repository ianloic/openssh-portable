// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include <zircon/types.h>

struct timeval;

int chroot(const char *path);
int fuchsia_launch_child(const char *command, int in, int out, int err, bool transform);

/* This implements the subset of select() functionality used by openssh */
/* Uses void* instead of fd_set* for the read/write fd sets since this compat header is included in
 * smult_curve25519_ref.c, which declares a completely unrelated function called select() */
/* Doesn't export exceptfds */
int fuchsia_select(int nfds, void* readfds, void* writefds, struct timeval *timeout);

#define CUSTOM_SYS_AUTH_PASSWD

