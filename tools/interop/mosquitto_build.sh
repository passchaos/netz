#!/usr/bin/env bash

# Shared audited Mosquitto resolver. The caller must define `work`; the build
# stays in that disposable directory and never mutates the reference checkout.
mosquitto_root=${MOSQUITTO_ROOT:-"$HOME/Work/mosquitto"}
mosquitto_binary=${MOSQUITTO_BIN:-}
expected_mosquitto_commit=${MOSQUITTO_COMMIT:-5cd25465}

build_mosquitto() {
  local build_dir="$work/mosquitto-build"
  local multiarch
  multiarch=$(cc -print-multiarch 2>/dev/null || true)
  local system_cjson="/usr/lib/$multiarch/libcjson.so.1"
  local cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
    -DWITH_APPS=OFF -DWITH_CLIENTS=OFF -DWITH_DOCS=OFF
    -DWITH_PLUGINS=OFF -DWITH_TESTS=OFF -DWITH_TLS=OFF
    -DWITH_WEBSOCKETS=OFF -DWITH_UNIX_SOCKETS=OFF
  )
  if [[ -n "${CJSON_INCLUDE_DIR:-}" ]]; then
    cmake_args+=("-DCJSON_INCLUDE_DIR=$CJSON_INCLUDE_DIR")
  elif [[ -f /usr/include/cjson/cJSON.h ]]; then
    cmake_args+=("-DCJSON_INCLUDE_DIR=/usr/include")
  elif [[ -n "$multiarch" && -e "$system_cjson" ]]; then
    mkdir -p "$work/cjson-include/cjson"
    curl -fsSL \
      https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.17/cJSON.h \
      -o "$work/cjson-include/cjson/cJSON.h"
    echo 'c01a8ca5609bb2c956dd1ae836d5d926ec68153ecebc5a75ea0febc2e076da8d  cJSON.h' \
      | (cd "$work/cjson-include/cjson" && sha256sum -c -) >&2
    cmake_args+=("-DCJSON_INCLUDE_DIR=$work/cjson-include")
  fi
  if [[ -n "${CJSON_LIBRARY:-}" ]]; then
    cmake_args+=("-DCJSON_LIBRARY=$CJSON_LIBRARY")
  elif [[ -n "$multiarch" && ! -e "/usr/lib/$multiarch/libcjson.so" &&
        -e "$system_cjson" ]]; then
    ln -s "$system_cjson" "$work/libcjson.so"
    cmake_args+=("-DCJSON_LIBRARY=$work/libcjson.so")
  fi
  cmake -S "$mosquitto_root" -B "$build_dir" "${cmake_args[@]}" \
    >"$work/mosquitto-configure.log" || {
      cat "$work/mosquitto-configure.log" >&2
      echo 'Mosquitto build dependencies are unavailable; install its documented build dependencies (including cJSON development headers).' >&2
      return 1
    }
  cmake --build "$build_dir" --target mosquitto -j2 \
    >"$work/mosquitto-build.log" || {
      cat "$work/mosquitto-build.log" >&2
      return 1
    }
  printf '%s\n' "$build_dir/src/mosquitto"
}

resolve_mosquitto() {
  if [[ -n "$mosquitto_binary" ]]; then
    [[ -x "$mosquitto_binary" ]] || {
      echo "MOSQUITTO_BIN is not executable: $mosquitto_binary" >&2
      return 1
    }
    printf '%s\n' "$mosquitto_binary"
    return
  fi
  if [[ ! -f "$mosquitto_root/CMakeLists.txt" ]]; then
    echo "Mosquitto checkout not found at $mosquitto_root" >&2
    echo 'set MOSQUITTO_ROOT to an audited local checkout' >&2
    return 1
  fi
  local actual_commit
  actual_commit=$(git -C "$mosquitto_root" rev-parse --short HEAD)
  if [[ "$actual_commit" != "$expected_mosquitto_commit" ]]; then
    echo "Mosquitto checkout is $actual_commit; expected $expected_mosquitto_commit" >&2
    echo 'set MOSQUITTO_COMMIT explicitly when auditing another revision' >&2
    return 1
  fi
  local candidate
  for candidate in \
    "$mosquitto_root/build/src/mosquitto" \
    "$mosquitto_root/src/mosquitto"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  build_mosquitto
}
