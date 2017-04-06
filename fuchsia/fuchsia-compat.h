// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include <magenta/types.h>

int chroot(const char *path);
int fuchsia_launch_child(const char *command, int in, int out, int err);

#define CUSTOM_SYS_AUTH_PASSWD

