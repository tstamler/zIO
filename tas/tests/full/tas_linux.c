#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include <tas_ll.h>

#include "../testutils.h"

static int start_testcase(int (*entry)(void *), void *data);
static int run_child(int (*entry)(void *), void *data);
static int setgroups_deny(void);
static int set_idmap(const char *path, int new_id, int env_id);

static int simple_cmd(const char *path, char * const args[])
{
  int nret;
  pid_t pid, npid;

  pid = fork();
  if (pid == 0) {
    /* in child */
    nret = execvp(path, args);
    perror("simple_cmd: execvp failed");
    exit(1);
  } else if (pid < 0) {
    perror("fork failed");
    return -1;
  } else {
    npid = waitpid(pid, &nret, 0);
    if (npid < 0) {
      perror("waitpid failed");
      return 1;
    }

    if (WIFEXITED(nret)) {
      return WEXITSTATUS(nret);
    } else {
      return 1;
    }
  }
}

static pid_t start_tas(void)
{
  int ready_fd, ret;
  pid_t pid;
  char readyfdopt[32];
  uint64_t x = 0;

  /* create event notification fd */
  if ((ready_fd = eventfd(0, 0)) < 0) {
    perror("eventfd for ready fd failed");
    return -1;
  }

  sprintf(readyfdopt, "--ready-fd=%d", ready_fd);

  /* fork off tas */
  pid = fork();
  if (pid == 0) {
    /* in child */
    execl("tas/tas", "--fp-cores-max=1", "--fp-no-ints", "--fp-no-xsumoffload",
        "--fp-no-autoscale", "--fp-no-hugepages", "--dpdk-extra=--vdev",
        "--dpdk-extra=eth_tap0,iface=vethtas1",
        "--dpdk-extra=--no-shconf", "--dpdk-extra=--no-huge",
        "--ip-addr=192.168.1.1/24", readyfdopt, NULL);

    perror("exec failed");
    exit(1);
  } else if (pid < 0) {
    /* fork failed */
    return -1;
  }

  /* wait for TAS to be ready */
  if (read(ready_fd, &x, sizeof(x)) < 0) {
    perror("read from readyfd failed");
    goto out_error;
  } else if (x != 1) {
    fprintf(stderr, "read unexpected value from ready fd\n");
    goto out_error;
  }

  return pid;

out_error:
  kill(pid, SIGTERM);
  waitpid(pid, &ret, 0);
  return -1;
}

static int test_1(void *data)
{
  static char *ip_addr_cmd[] = {"ip", "addr", "add", "192.168.1.2/24", "dev",
    "vethtas1", NULL };
  static char *ip_up_cmd[] = {"ip", "link", "set", "vethtas1", "up", NULL };

  pid_t tas_pid, npid;
  int nret, ret = 0;

  /* start tas */
  if ((tas_pid = start_tas()) < 0) {
    fprintf(stderr, "start_tas failed\n");
    return 1;
  }

  /* set ip address for TAS interface and bring it up */
  if (simple_cmd(ip_addr_cmd[0], ip_addr_cmd) != 0) {
    fprintf(stderr, "ip addr failed\n");
    return 1;
  }
  if (simple_cmd(ip_up_cmd[0], ip_up_cmd) != 0) {
    fprintf(stderr, "ip set up failed\n");
    return 1;
  }

  /* connect to tas */
  if (flextcp_init() != 0) {
    fprintf(stderr, "flextcp_init failed\n");
    ret = 1;
    goto out;
  }

  /* create context */
  struct flextcp_context context;
  if (flextcp_context_create(&context) != 0) {
    fprintf(stderr, "flextcp_context_create failed\n");
    ret = 1;
    goto out;
  }

  /* prepare listener */
  struct flextcp_listener listen;
  if (flextcp_listen_open(&context, &listen, 1234, 32,
              FLEXTCP_LISTEN_REUSEPORT) != 0)
  {
    fprintf(stderr, "flextcp_listen_open failed\n");
    ret = 1;
    goto out;
  }

  /* wait for listener to open */
  struct flextcp_event evs[32];
  int n;
  do {
    if ((n = flextcp_context_poll(&context, 1, evs)) < 0) {
      fprintf(stderr, "flextcp_context_poll failed\n");
      ret = 1;
      goto out;
    }

    if (n == 0)
      continue;

    if (n == 1 && evs[0].event_type == FLEXTCP_EV_LISTEN_OPEN &&
        evs[0].ev.listen_open.status == 0)
      break;

    fprintf(stderr, "unexpected event: %u\n", evs[0].event_type);
    ret = 1;
    goto out;
  } while (1);

  /* create linux socket */
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    ret = 1;
    goto out;
  }

  /* set socket to nonblocking */
  int flag;
  if ((flag = fcntl(sock, F_GETFL, 0)) == -1) {
    perror("fcntl getfl failed");
    ret = 1;
    goto out;
  }
  flag |= O_NONBLOCK;
  if (fcntl(sock, F_SETFL, flag) == -1) {
    perror("fcntl setfl failed");
    abort();
  }

  /* connect to listener */
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0xc0a80101);
  addr.sin_port = htons(1234);
  if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) != -1 && errno == EINPROGRESS) {
    perror("connect failed");
    ret = 1;
    goto out;
  }

  /* wait for newconn event */
  do {
    if ((n = flextcp_context_poll(&context, 1, evs)) < 0) {
      fprintf(stderr, "flextcp_context_poll failed\n");
      ret = 1;
      goto out;
    }

    if (n == 0)
      continue;

    if (n == 1 && evs[0].event_type == FLEXTCP_EV_LISTEN_NEWCONN)
      break;

    fprintf(stderr, "unexpected event: %u\n", evs[0].event_type);
    ret = 1;
    goto out;
  } while (1);

  /* accept connection */
  struct flextcp_connection conn;
  if (flextcp_listen_accept(&context, &listen, &conn) != 0) {
    fprintf(stderr, "accept failed");
    ret = 1;
    goto out;
  }

  /* wait for accepted event */
  do {
    if ((n = flextcp_context_poll(&context, 1, evs)) < 0) {
      fprintf(stderr, "flextcp_context_poll failed\n");
      ret = 1;
      goto out;
    }

    if (n == 0)
      continue;

    if (n == 1 && evs[0].event_type == FLEXTCP_EV_LISTEN_ACCEPT &&
        evs[0].ev.listen_accept.status == 0)
      break;

    fprintf(stderr, "unexpected event: %u\n", evs[0].event_type);
    ret = 1;
    goto out;
  } while (1);

  /* wait for connection to be established */
  socklen_t slen;
  do {
    slen = sizeof(nret);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &nret, &slen) != 0) {
      perror("getsockopt failed");
      ret = 1;
      goto out;
    }

    if (nret == 0)
      break;
  } while (1);

  /* send some data */
  static char buffer[1024 * 32];
  ssize_t data_sent;
  do {
    data_sent = write(sock, buffer, sizeof(buffer));
  } while (data_sent == -1 && errno == EAGAIN);
  if (data_sent == -1) {
    perror("send failed");
    ret = 1;
    goto out;
  }

  /* wait for data event */
  ssize_t data_rxd = 0;

  while (data_rxd < data_sent) {
    time_t start_time = time(NULL);
    size_t rx_done = 0;
    do {
      if ((n = flextcp_context_poll(&context, 32, evs)) < 0) {
        fprintf(stderr, "flextcp_context_poll failed\n");
        ret = 1;
        goto out;
      }

      int i;
      for (i = 0; i < n; i++) {
        if (evs[i].event_type != FLEXTCP_EV_CONN_RECEIVED) {
          fprintf(stderr, "unexpected event: %u\n", evs[i].event_type);
          ret = 1;
          goto out;
        }

        rx_done += evs[i].ev.conn_received.len;
      }
    } while (time(NULL) - start_time < 1);

    if (flextcp_connection_rx_done(&context, &conn, rx_done) != 0) {
      fprintf(stderr, "flextcp_connection_rx_done failed\n");
      ret = 1;
      goto out;
    }

    data_rxd += rx_done;
  }

  fprintf(stderr, "success\n");
out:
  /* send sigterm to TAS */
  kill(tas_pid, SIGTERM);

  /* wait for tas to terminate */
  npid = waitpid(tas_pid, &nret, 0);
  if (npid < 0) {
    perror("waitpid failed");
    return 1;
  }

  return ret;
}

int main(int argc, char *argv[])
{
  return start_testcase(test_1, NULL);
}

static int start_testcase(int (*entry)(void *), void *data)
{
  int ret = 0, nret;
  int env_uid, env_gid;
  pid_t pid, npid;

  pid = fork();
  if (pid == 0) {
    /* in child */
    env_uid = getuid();
    env_gid = getgid();

    /* in child */
    if (unshare(CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWNET)
        != 0)
    {
      perror("unshare user namespace failed");
      exit(EXIT_FAILURE);
    }

    if (setgroups_deny() != 0) {
      perror("setgroups deny failed");
      exit(EXIT_FAILURE);
    }

    if (set_idmap("/proc/self/uid_map", 0, env_uid) != 0) {
      perror("map uid failed");
      exit(EXIT_FAILURE);
    }

    if (set_idmap("/proc/self/gid_map", 0, env_gid) != 0) {
      perror("map gid failed");
      exit(EXIT_FAILURE);
    }

    exit(run_child(entry, data));
  } else if (pid > 0) {
    /* in parent */
    npid = waitpid(pid, &nret, 0);
    if (npid < 0) {
      perror("waitpid failed");
      return 1;
    }

    if (WIFEXITED(nret)) {
      ret = WEXITSTATUS(nret);
    } else {
      ret = 1;
    }
  } else {
    ret = 1;
  }

  return ret;
}

static int run_child(int (*entry)(void *), void *data)
{
  pid_t pid, npid;
  int ret;

  umask(0);
  pid = fork();
  if (pid == 0) {
    /* in child */

    umask(0022);

    return entry(data);
  } else if (pid > 0) {
    /* in parent */
    npid = waitpid(pid, &ret, 0);
    if (npid < 0) {
      perror("waitpid failed");
      return 1;
    }

    if (WIFEXITED(ret)) {
      return WEXITSTATUS(ret);
    } else {
      return 1;
    }
  } else {
    perror("fork failed");
  }

  return 0;
}


static int setgroups_deny(void)
{
    int fd;
    ssize_t ret, len;
    const char *deny_str = "deny";

    if ((fd = open("/proc/self/setgroups", O_WRONLY)) == -1) {
        perror("setgroups_deny: open failed");
        return -1;
    }

    len = strlen(deny_str);
    ret = write(fd, deny_str, len);
    close(fd);
    if (ret < 0) {
        perror("setgroups_deny: write failed");
        return -1;
    } else if (ret != len) {
        perror("setgroups_deny: partial write");
        return -1;
    }

    return 0;
}

static int set_idmap(const char *path, int new_id, int env_id)
{
    int fd;
    ssize_t ret, len;
    char str[64];

    if (snprintf(str, sizeof(str), "%u %u 1", new_id, env_id) >=
        (ssize_t) sizeof(str))
    {
        perror("set_idmap: buffer too small");
        return -1;
    }
    len = strlen(str);

    if ((fd = open(path, O_WRONLY)) == -1) {
        perror("set_idmap: open failed");
        return -1;
    }

    ret = write(fd, str, len);
    close(fd);
    if (ret < 0) {
        perror("set_idmap: write failed");
        return -1;
    } else if (ret != len) {
        perror("set_idmap: partial write");
        return -1;
    }

    return 0;
}


