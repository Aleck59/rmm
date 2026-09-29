#!/usr/bin/env bash
# Build and package InvMon release artifacts into dist/.
#
# Produces, for each target:
#   - server: invmon-server-<ver>-windows-<arch>.zip  (+ linux tar.gz)
#   - agent:  invmon-agent-<ver>-windows-<arch>.zip
# Each Windows package bundles the install/uninstall scripts, an example
# config, README and LICENSE. A SHA256SUMS file covers everything.
#
# Environment:
#   VERSION            release version (default: `git describe` or 0.0.0-dev)
#   SKIP_WEB=1         do not rebuild the SPA (use the current embed dir)
#   INVMON_GO_WIN7     path to a go-legacy-win7 `go` binary; when set, also
#                      builds -win7 agent packages for 386/amd64
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PKG="github.com/Aleck59/rmm"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
VERSION="${VERSION#v}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X ${PKG}/internal/buildinfo.Version=${VERSION} -X ${PKG}/internal/buildinfo.Commit=${COMMIT} -X ${PKG}/internal/buildinfo.Date=${DATE}"

DIST="${ROOT}/dist"
STAGE="${DIST}/stage"
rm -rf "${DIST}"
mkdir -p "${DIST}" "${STAGE}"

echo ">> InvMon ${VERSION} (commit ${COMMIT}, ${DATE})"

# ---- 1. Web SPA -------------------------------------------------------------
if [[ "${SKIP_WEB:-0}" != "1" ]]; then
    echo ">> building web SPA"
    (cd web && pnpm install --frozen-lockfile && pnpm build)
else
    echo ">> SKIP_WEB=1, using existing internal/webui/dist"
fi

# ---- helpers ----------------------------------------------------------------
# build_bin <goos> <goarch> <cmd> <output-path> [go-binary]
build_bin() {
    local goos="$1" goarch="$2" cmd="$3" out="$4" gobin="${5:-go}"
    local note="" toolchain="${GOTOOLCHAIN:-auto}"
    if [[ "${gobin}" != "go" ]]; then
        note=" (win7 toolchain)"
        # Never let the fork switch to an upstream toolchain, which would
        # silently drop Windows 7 support from the binary.
        toolchain=local
    fi
    echo ">> build ${cmd} ${goos}/${goarch}${note}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" GOTOOLCHAIN="${toolchain}" \
        "${gobin}" build -trimpath -ldflags "${LDFLAGS}" -o "${out}" "./cmd/${cmd}"
}

# zip_dir <dir> <zip-path>  (zip contents of dir, stored relative)
zip_dir() {
    local dir="$1" zip="$2"
    (cd "$(dirname "${dir}")" && zip -qr "${zip}" "$(basename "${dir}")")
}

package_server_windows() {
    local arch="$1"
    local name="invmon-server-${VERSION}-windows-${arch}"
    local dir="${STAGE}/${name}"
    mkdir -p "${dir}"
    build_bin windows "${arch}" invmon-server "${dir}/invmon-server.exe"
    cp packaging/windows/server/install.ps1 packaging/windows/server/uninstall.ps1 \
       packaging/windows/server/server.example.yaml packaging/windows/server/README.txt \
       LICENSE "${dir}/"
    zip_dir "${dir}" "${DIST}/${name}.zip"
}

package_agent_windows() {
    local arch="$1" suffix="${2:-}" gobin="${3:-go}"
    local name="invmon-agent-${VERSION}-windows-${arch}${suffix}"
    local dir="${STAGE}/${name}"
    mkdir -p "${dir}"
    build_bin windows "${arch}" invmon-agent "${dir}/invmon-agent.exe" "${gobin}"
    cp packaging/windows/agent/install.ps1 packaging/windows/agent/uninstall.ps1 \
       packaging/windows/agent/agent.example.yaml packaging/windows/agent/README.txt \
       LICENSE "${dir}/"
    zip_dir "${dir}" "${DIST}/${name}.zip"
}

package_server_linux() {
    local arch="$1"
    local name="invmon-server-${VERSION}-linux-${arch}"
    local dir="${STAGE}/${name}"
    mkdir -p "${dir}"
    build_bin linux "${arch}" invmon-server "${dir}/invmon-server"
    cp packaging/windows/server/server.example.yaml "${dir}/server.example.yaml"
    cp LICENSE "${dir}/"
    (cd "${STAGE}" && tar -czf "${DIST}/${name}.tar.gz" "${name}")
}

# ---- 2. Build & package -----------------------------------------------------
for arch in amd64 386 arm64; do
    package_server_windows "${arch}"
    package_agent_windows "${arch}"
done
package_server_linux amd64

# Windows 7 / 8.1 agent builds via the go-legacy-win7 toolchain (optional).
if [[ -n "${INVMON_GO_WIN7:-}" ]]; then
    for arch in 386 amd64; do
        package_agent_windows "${arch}" "-win7" "${INVMON_GO_WIN7}"
    done
fi

# ---- 3. Checksums -----------------------------------------------------------
rm -rf "${STAGE}"
(cd "${DIST}" && sha256sum -- * > SHA256SUMS)

echo ">> artifacts:"
ls -1 "${DIST}"
