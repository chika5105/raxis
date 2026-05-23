#!/usr/bin/env bash
# notarize.sh — codesign + notarytool + Gatekeeper wrapper.
#
# Normative reference: raxis/specs/v2/release-and-distribution.md
# §6 ("Apple notarization").
#
# Reads:
#   APPLE_DEVELOPER_ID_APPLICATION_P12          (base64 of a .p12 bundle)
#   APPLE_DEVELOPER_ID_APPLICATION_PASSWORD     (.p12 password)
#   APPLE_NOTARIZATION_API_KEY_ID
#   APPLE_NOTARIZATION_API_KEY_ISSUER_ID
#   APPLE_NOTARIZATION_API_KEY_P8               (base64 of an App Store Connect API key)
#
# Argument: path to a directory containing the Mach-O binaries to
# sign + notarize (typically `bin/`).
#
# This script is invoked by .github/workflows/release.yml on the
# macos-14 runners only. It MUST NOT be run on a developer laptop
# without the production Apple Developer ID — local-build users
# follow raxis/specs/v2/release-and-distribution.md §8 instead.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <bin-dir>" >&2
    exit 64
fi

bin_dir="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
entitlements="${script_dir}/../raxis.entitlements"

if [[ ! -d "${bin_dir}" ]]; then
    echo "notarize.sh: bin dir does not exist: ${bin_dir}" >&2
    exit 66
fi
if [[ ! -f "${entitlements}" ]]; then
    echo "notarize.sh: entitlements file missing: ${entitlements}" >&2
    exit 66
fi

required=(
    APPLE_DEVELOPER_ID_APPLICATION_P12
    APPLE_DEVELOPER_ID_APPLICATION_PASSWORD
    APPLE_NOTARIZATION_API_KEY_ID
    APPLE_NOTARIZATION_API_KEY_ISSUER_ID
    APPLE_NOTARIZATION_API_KEY_P8
)
for v in "${required[@]}"; do
    if [[ -z "${!v:-}" ]]; then
        echo "notarize.sh: required env var not set: ${v}" >&2
        exit 78
    fi
done

# Per the spec: secrets MUST NEVER be written to durable disk on
# the runner. We materialise them under $RUNNER_TEMP (auto-deleted
# at job end) and `chmod 0600` everything.
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
chmod 0700 "${work}"

p12="${work}/cert.p12"
api_key="${work}/notarytool.p8"

# `--decode` not `-d` — old `base64` impls vary.
printf '%s' "${APPLE_DEVELOPER_ID_APPLICATION_P12}" | base64 --decode > "${p12}"
printf '%s' "${APPLE_NOTARIZATION_API_KEY_P8}"      | base64 --decode > "${api_key}"
chmod 0600 "${p12}" "${api_key}"

# Transient keychain. Old keychains from previous runs are
# deleted unconditionally to avoid carrying leaked state forward.
keychain="${work}/build.keychain"
keychain_pw="$(openssl rand -hex 16)"
cleanup() {
    security delete-keychain "${keychain}" >/dev/null 2>&1 || true
    rm -rf "${work}"
}
trap cleanup EXIT

security create-keychain  -p "${keychain_pw}" "${keychain}"
security set-keychain-settings -lut 21600     "${keychain}"
security unlock-keychain  -p "${keychain_pw}" "${keychain}"
security import "${p12}" \
    -k "${keychain}" \
    -P "${APPLE_DEVELOPER_ID_APPLICATION_PASSWORD}" \
    -T /usr/bin/codesign
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s -k "${keychain_pw}" "${keychain}"

# Identify the codesign certificate. `find-identity -v -p codesigning`
# lists only Developer ID Application identities; we expect exactly
# one.
identity_line="$(security find-identity -v -p codesigning "${keychain}" | grep "Developer ID Application" | head -1 || true)"
if [[ -z "${identity_line}" ]]; then
    echo "notarize.sh: no Developer ID Application identity in keychain" >&2
    exit 75
fi
# Extract the certificate's CN (the substring inside the double quotes).
identity="$(printf '%s' "${identity_line}" | sed -E 's/^.*"([^"]+)".*$/\1/')"
echo "notarize.sh: signing as: ${identity}"

# Codesign every Mach-O in $bin_dir.
shopt -s nullglob
for binary in "${bin_dir}"/*; do
    if [[ ! -f "${binary}" ]]; then continue; fi
    # Skip non-Mach-O files (license texts, READMEs, anything that
    # ended up under bin/ accidentally).
    if ! file "${binary}" | grep -q "Mach-O"; then
        echo "notarize.sh: skipping non-Mach-O: ${binary}"
        continue
    fi
    echo "notarize.sh: codesigning ${binary}"
    codesign --force --options runtime --timestamp \
             --sign "${identity}" \
             --entitlements "${entitlements}" \
             --keychain "${keychain}" \
             "${binary}"
done

# Bundle the signed bin/ for notarytool submission. notarytool
# accepts .zip archives.
zip="${work}/raxis-bin.zip"
( cd "${bin_dir}/.." && zip -r "${zip}" "$(basename "${bin_dir}")" >/dev/null )

echo "notarize.sh: submitting to Apple notarization servers"
submit_log="${work}/notary-submit.log"
set +e
xcrun notarytool submit "${zip}" \
    --key       "${api_key}" \
    --key-id    "${APPLE_NOTARIZATION_API_KEY_ID}" \
    --issuer    "${APPLE_NOTARIZATION_API_KEY_ISSUER_ID}" \
    --wait      \
    --timeout   "${APPLE_NOTARIZATION_TIMEOUT:-30m}" \
    2>&1 | tee "${submit_log}"
submit_status=${PIPESTATUS[0]}
set -e
if [[ ${submit_status} -ne 0 ]]; then
    submission_id="$(grep -E '^[[:space:]]*id: ' "${submit_log}" | tail -1 | awk '{print $2}' || true)"
    if [[ -n "${submission_id}" ]]; then
        echo "notarize.sh: Apple submission did not finish successfully; submission id: ${submission_id}" >&2
        xcrun notarytool info "${submission_id}" \
            --key       "${api_key}" \
            --key-id    "${APPLE_NOTARIZATION_API_KEY_ID}" \
            --issuer    "${APPLE_NOTARIZATION_API_KEY_ISSUER_ID}" >&2 || true
        xcrun notarytool log "${submission_id}" \
            --key       "${api_key}" \
            --key-id    "${APPLE_NOTARIZATION_API_KEY_ID}" \
            --issuer    "${APPLE_NOTARIZATION_API_KEY_ISSUER_ID}" >&2 || true
    fi
    exit "${submit_status}"
fi

echo "notarize.sh: raw Mach-O command-line tools cannot be stapled; Gatekeeper will validate the notarization ticket by cdhash"

# Self-test: every binary must have a strict valid Developer ID
# signature and a notarization ticket visible to Gatekeeper. On modern
# macOS, `spctl --type exec` treats a bare Mach-O as "not an app" even
# when notarization succeeded; `--type install` is the stable way to
# check the online notarization ticket for raw command-line tools.
echo "notarize.sh: running Gatekeeper self-test"
for binary in "${bin_dir}"/*; do
    if [[ ! -f "${binary}" ]]; then continue; fi
    if ! file "${binary}" | grep -q "Mach-O"; then continue; fi

    codesign --verify --strict --verbose=4 "${binary}"
    signature_details="$(codesign -dvvv "${binary}" 2>&1)"
    if ! grep -q "Authority=Developer ID Application" <<<"${signature_details}"; then
        echo "notarize.sh: FAIL: ${binary} is not signed by a Developer ID Application identity" >&2
        printf '%s\n' "${signature_details}" >&2
        exit 75
    fi
    if ! grep -q "flags=.*runtime" <<<"${signature_details}"; then
        echo "notarize.sh: FAIL: ${binary} is not signed with hardened runtime" >&2
        printf '%s\n' "${signature_details}" >&2
        exit 75
    fi

    accepted=0
    last_assessment=""
    for attempt in {1..18}; do
        set +e
        last_assessment="$(spctl --assess --type install -vv "${binary}" 2>&1)"
        assess_status=$?
        set -e
        if [[ ${assess_status} -eq 0 ]] &&
           grep -q "accepted" <<<"${last_assessment}" &&
           grep -q "Notarized Developer ID" <<<"${last_assessment}"; then
            accepted=1
            break
        fi
        if [[ ${attempt} -lt 18 ]]; then
            echo "notarize.sh: Gatekeeper has not observed notarization for ${binary}; retry ${attempt}/17"
            sleep 10
        fi
    done
    if [[ ${accepted} -ne 1 ]]; then
        echo "notarize.sh: FAIL: ${binary} did not pass notarized Gatekeeper assessment" >&2
        printf '%s\n' "${last_assessment}" >&2
        exit 75
    fi
done

echo "notarize.sh: success"
