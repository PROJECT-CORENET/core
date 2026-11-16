#!/usr/bin/env bash
# Собрать Rust-ядро для приложений Apple:
#   APP/CoreKit/CoreFFI.xcframework           — статические библиотеки (iOS, iOS Simulator, macOS)
#   APP/CoreKit/Sources/CoreKit/Generated/    — Swift-обёртки UniFFI
#
# Использование: CORE/scripts/build-apple.sh [debug|release]   (по умолчанию release)
set -euo pipefail

PROFILE="${1:-release}"
CORE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PKG_DIR="$CORE_DIR/../APP/CoreKit"
BUILD_DIR="$CORE_DIR/target/apple"
# Отдельный target-каталог: не смешиваем артефакты с dev-сборками другим тулчейном.
export CARGO_TARGET_DIR="$CORE_DIR/target/apple-build"
OUT="$CARGO_TARGET_DIR"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)

# Cargo и rustc из rustup stable — даже если в PATH напрямую лежит другой тулчейн.
if command -v rustup >/dev/null; then
  CARGO=("$(rustup which --toolchain stable cargo)")
  export RUSTC="$(rustup which --toolchain stable rustc)"
else
  CARGO=(cargo)
fi
# MACOSX_DEPLOYMENT_TARGET не задаём: с ним ld из Xcode 27 собирает proc-macro dylib, которые
# не загружаются (mis-aligned LINKEDIT). Минимальная версия по умолчанию ниже 26 — линкуется без проблем.

cd "$CORE_DIR"
PROFILE_DIR="$PROFILE"
[ "$PROFILE" = "debug" ] && PROFILE_FLAG=() || PROFILE_FLAG=(--profile "$PROFILE")
[ "$PROFILE" = "debug" ] && PROFILE_DIR=debug

echo "🦀 building core-ffi ($PROFILE) for: ${TARGETS[*]}"
for t in "${TARGETS[@]}"; do
  "${CARGO[@]}" build -p core-ffi --lib "${PROFILE_FLAG[@]}" --target "$t"
done

echo "🔧 generating Swift bindings"
rm -rf "$BUILD_DIR/gen" "$BUILD_DIR/headers" && mkdir -p "$BUILD_DIR/gen" "$BUILD_DIR/headers"
"${CARGO[@]}" run -q -p core-ffi --bin uniffi-bindgen -- generate \
  --library "$OUT/aarch64-apple-darwin/$PROFILE_DIR/libcore_ffi.dylib" \
  --language swift --out-dir "$BUILD_DIR/gen"
cp "$BUILD_DIR/gen/core_ffiFFI.h" "$BUILD_DIR/headers/"
cp "$BUILD_DIR/gen/core_ffiFFI.modulemap" "$BUILD_DIR/headers/module.modulemap"

echo "📦 creating CoreFFI.xcframework"
rm -rf "$PKG_DIR/CoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$OUT/aarch64-apple-ios/$PROFILE_DIR/libcore_ffi.a" -headers "$BUILD_DIR/headers" \
  -library "$OUT/aarch64-apple-ios-sim/$PROFILE_DIR/libcore_ffi.a" -headers "$BUILD_DIR/headers" \
  -library "$OUT/aarch64-apple-darwin/$PROFILE_DIR/libcore_ffi.a" -headers "$BUILD_DIR/headers" \
  -output "$PKG_DIR/CoreFFI.xcframework" >/dev/null

mkdir -p "$PKG_DIR/Sources/CoreKit/Generated"
cp "$BUILD_DIR/gen/core_ffi.swift" "$PKG_DIR/Sources/CoreKit/Generated/core_ffi.swift"
echo "✅ done: $(cd "$PKG_DIR" && pwd)"
