"""Internal POSIX trampoline: fchdir without unsafe preexec_fn in a threaded parent."""

import os
import sys


def main():
    cwd_fd, status_fd = int(sys.argv[1]), int(sys.argv[2])
    try:
        os.fchdir(cwd_fd)
        os.close(cwd_fd)
        os.set_inheritable(status_fd, False)
        os.execve(sys.argv[3], sys.argv[3:], os.environ)
    except OSError:
        os.write(status_fd, b"exec_failed")
        os._exit(127)


if __name__ == "__main__":
    main()
