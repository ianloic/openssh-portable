#include <pwd.h>
#include <sys/types.h>

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
