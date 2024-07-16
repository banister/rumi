# WHAT

Rumi is a process introspection tool for macOS. It enables you to trace the subprocesses that are executed by a given
process, trace process-specific network packets as well as view active sockets.

# SETUP

- Install Vcpkg:
`git clone https://github.com/microsoft/vcpkg.git`
`cd vcpkg`
`./bootstrap-vcpkg.sh  -disableMetrics`
Change `-DCMAKE_TOOLCHAIN_FILE` in `build.sh` to point to yours vcpkg installation

# BUILD

- Build using `./build.sh`

# RUN

```
$ sudo rumi -h
Runtime ruminations
Usage:
  rumi [OPTION...]

  -h, --help         Display this help message.
  -a, --analyze      Analyze traffic.
  -s, --sockets      Show socket information.
  -e, --exec         Show process execs.
  -p, --process arg  The processes to observe (either pid or name)
  -P, --parent arg   The parent processes to observe (either pid or name)
  -c, --cols arg     The display columns to use for output.
  -f, --format arg   Set format string.
  -v, --verbose      Verbose output.
  -4, --inet         IPv4 only.
  -6, --inet6        IPv6 only.
```

### Show exec() calls

```
$ sudo rumi -e
pid: 61853 ppid: 67853 - ps -p67600
pid: 61854 ppid: 67853 - sleep 1
pid: 61857 ppid: 61856 - git rev-parse --git-dir
pid: 61857 ppid: 61856 - git rev-parse --git-dir
pid: 61859 ppid: 61858 - git config --get oh-my-zsh.hide-info
pid: 61859 ppid: 61858 - git config --get oh-my-zsh.hide-info
pid: 61861 ppid: 61860 - git symbolic-ref --short HEAD
pid: 61861 ppid: 61860 - git symbolic-ref --short HEAD
pid: 61864 ppid: 61863 - git config --get oh-my-zsh.hide-dirty
pid: 61864 ppid: 61863 - git config --get oh-my-zsh.hide-dirty
pid: 61867 ppid: 61865 - tail -n 1
```

### Trace application specific network packets

```
$ sudo rumi -a
qbittorrent UDP 192.168.254.103:39873 > 218.144.126.73:60734
qbittorrent UDP 192.168.254.103:39873 > 218.144.126.73:60734
qbittorrent UDP 192.168.254.103:39873 > 218.144.126.73:60734
```

### Show process socket information

```
$ sudo rumi -s  -p pia-daemon
IPv4
==
TCP 127.0.0.1:49736 -> 127.0.0.1:49735 pia-daemon
TCP 127.0.0.1:49737 -> 127.0.0.1:49735 pia-daemon
TCP 127.0.0.1:49735 -> 0.0.0.0:0 pia-daemon
TCP 127.0.0.1:49738 -> 127.0.0.1:49735 pia-daemon
```
