#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Read-only access layout inventory. Never install keys or test/load host keys.
set -eu
[ "$(uname -s)" = Linux ] || { echo E_LINUX_REQUIRED >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo E_ROOT_METADATA_REQUIRED >&2; exit 2; }
[ "$#" = 4 ] || { echo 'Usage: user client-ipv4 server-ipv4 core-container' >&2; exit 2; }
target_user=$1;client_ip=$2;server_ip=$3;target_container=$4
case "$target_user" in ''|*[!a-z0-9_-]*|[0-9-]*) echo E_USER_NAME >&2; exit 2 ;; esac
[ "${#target_user}" -le 32 ] || { echo E_USER_NAME >&2; exit 2; }
case "$target_container" in ''|-*|*[!a-zA-Z0-9_.-]*) echo E_CONTAINER_NAME >&2; exit 2 ;; esac
for address in "$client_ip" "$server_ip"; do
  case "$address" in ''|*[!0-9.]*) echo E_IPV4_REQUIRED >&2; exit 2 ;; esac
  printf '%s\n' "$address" | awk -F . 'NF!=4{exit 2} {for(i=1;i<=4;i++)if($i!~/^[0-9]+$/||length($i)>3||$i+0>255)exit 2}' || {
    echo E_IPV4_REQUIRED >&2; exit 2;
  }
done
echo 'PROFILE=x-aiap-nas-access-metadata-v1'
for tool in getent stat sshd visudo timeout install sha256sum flock docker; do
  location=$(command -v "$tool" 2>/dev/null || :)
  printf 'TOOL_%s=%s\n' "$tool" "${location:-unavailable}"
done
entry=$(getent passwd "$target_user" | awk -F : 'NF==7{printf "%s:%s:%s:%s:%s\n",$1,$3,$4,$6,$7}')
IFS=: read -r actual_user target_uid target_gid target_home target_shell <<EOF
$entry
EOF
[ "$actual_user" = "$target_user" ] || { echo E_ACCOUNT_METADATA >&2; exit 2; }
case "$target_uid:$target_gid" in *[!0-9:]*|:*|*:) echo E_ACCOUNT_METADATA >&2; exit 2 ;; esac
case "$target_home" in /*) ;; *) echo E_ACCOUNT_HOME >&2; exit 2 ;; esac
printf 'LOGIN_USER=%s\nUID=%s\nGID=%s\nHOME_PATH=%s\nSHELL_PATH=%s\n' \
  "$target_user" "$target_uid" "$target_gid" "$target_home" "$target_shell"
for candidate in "$target_home" "$target_home/.ssh" "$target_home/.ssh/authorized_keys"; do
  printf 'CANDIDATE_PATH=%s\n' "$candidate"
  if [ -L "$candidate" ]; then
    echo 'PATH_STATUS=symlink_no_content_read'
  elif [ -e "$candidate" ]; then
    stat -c 'PATH_METADATA=uid:%u,gid:%g,mode:%a,type:%F' -- "$candidate" 2>/dev/null || echo PATH_METADATA=unavailable
    if command -v getfacl >/dev/null 2>&1; then
      getfacl -c -n -- "$candidate" 2>/dev/null | awk 'NF && $0!~/^#/{print "PATH_ACL=" $0}'
    fi
  else
    echo PATH_STATUS=missing
  fi
done
sshd_bin=$(command -v sshd 2>/dev/null || :)
if [ -z "$sshd_bin" ]; then
  for candidate in /usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd; do
    if [ -x "$candidate" ]; then sshd_bin=$candidate;break;fi
  done
fi
printf 'SSH_CONFIG_CONTEXT=user=%s,addr=%s,host=%s,laddr=%s,lport=22\n' "$target_user" "$client_ip" "$client_ip" "$server_ip"
printf 'SSHD_PROBE_BINARY=%s\n' "${sshd_bin:-unavailable}"
echo 'SSH_CONFIG_SCOPE=default_configuration_only_runtime_flags_and_reverse_hostname_not_verified'
if command -v pgrep >/dev/null 2>&1; then
  listener_pid=$(pgrep -xo sshd 2>/dev/null || :)
  case "$listener_pid" in ''|*[!0-9]*) listener_pid= ;; esac
  if [ -n "$listener_pid" ] && [ -r "/proc/$listener_pid/cmdline" ] &&
     [ "$(stat -c %u -- "/proc/$listener_pid" 2>/dev/null || :)" = 0 ]; then
    # Only public config-path/override hints, never the whole command line.
    head -c 8192 "/proc/$listener_pid/cmdline" | tr '\000' ' ' |
      awk '{for(i=1;i<=NF;i++){if($i=="-f" && i<NF && $(i+1)~/^\//)print "SSHD_RUNTIME_CONFIG_HINT=" $(i+1);if($i~/^-o/)overrides=1}}
           END{print "SSHD_RUNTIME_OVERRIDE_PRESENT=" (overrides?"yes":"no")}'
  else
    echo SSHD_RUNTIME_HINT=unavailable
  fi
fi
if [ -n "$sshd_bin" ]; then
  if settings=$(
    { "$sshd_bin" -G -C "user=$target_user,addr=$client_ip,host=$client_ip,laddr=$server_ip,lport=22" 2>/dev/null &&
      printf '__AIAP_CONFIG_DONE__\n'; } |
    awk '
      $0=="__AIAP_CONFIG_DONE__" {done=1;next}
      $1~/^(pubkeyauthentication|authorizedkeysfile|authorizedkeyscommanduser|strictmodes|permituserenvironment|authenticationmethods|pubkeyacceptedalgorithms|usedns)$/ {print "SSH_SETTING=" $0;count++}
      $1=="authorizedkeyscommand" || $1=="forcecommand" {print "SSH_SETTING=" $1 "_present " ($2=="none"?"no":"yes");count++}
      END {if(!done || count<2)exit 2}'
  ); then
    echo SSH_CONFIG_STATUS=parsed_without_host_key_testing
    printf '%s\n' "$settings"
  else
    echo SSH_CONFIG_STATUS=unavailable_no_T_or_t_fallback
  fi
else
  echo SSH_CONFIG_STATUS=unavailable_no_sshd
fi
if command -v docker >/dev/null 2>&1; then
  docker --host unix:///var/run/docker.sock inspect --type container \
    --format 'CORE_NAME={{.Name}} CORE_IMAGE_ID={{.Image}} CORE_RUNNING={{.State.Running}} CORE_USER={{.Config.User}}{{range .Mounts}}{{if eq .Destination "/data"}} CORE_DATA_MOUNT={{.Type}}:{{.Source}}:rw={{.RW}}{{end}}{{end}}' \
    "$target_container" 2>/dev/null || echo CORE_METADATA=unavailable
fi
echo 'PREFLIGHT_DONE_NO_CONFIGURATION_CHANGED'
