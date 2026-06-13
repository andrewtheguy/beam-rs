#!/bin/bash
set -e

# Build script for multi-architecture Linux binaries using Docker
# Builds for both AMD64 and ARM64 architectures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/target/linux"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.build"
IMAGE_NAME="beam-rs-builder"
VERSION="${VERSION:-latest}"

echo "beam-rs Multi-Architecture Build Script"
echo "============================================"
echo ""
echo "Build directory: $BUILD_DIR"
echo "Dockerfile: $DOCKERFILE"
echo "Version: $VERSION"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker from https://www.docker.com/"
    exit 1
fi

# Check if buildx is available
if ! docker buildx version &> /dev/null; then
    echo "Error: Docker buildx is not available"
    echo "Please update Docker to a version that supports buildx"
    exit 1
fi

# Clean and create build directory to prevent stale binaries
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create or use existing buildx builder
BUILDER_NAME="beam-rs-builder"
if ! docker buildx inspect "$BUILDER_NAME" &> /dev/null; then
    echo "Creating buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use --driver docker-container
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Build for both platforms in parallel
echo ""
echo "Building for linux/amd64 and linux/arm64 in parallel..."
echo "--------------------------------------------------------"

docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --file "$DOCKERFILE" \
    --target export \
    --output type=local,dest="$BUILD_DIR" \
    "$SCRIPT_DIR"

echo ""
echo "Organizing binaries..."
echo "----------------------"

# The output structure will have platform-specific subdirectories
# Move and rename binaries
for arch in amd64 arm64; do
    archdir="$BUILD_DIR/linux_${arch}"
    if [ -d "$archdir" ]; then
        for bin in beam-rs; do
            if [ -f "$archdir/$bin" ]; then
                mv "$archdir/$bin" "$BUILD_DIR/${bin}-linux-${arch}"
                echo "✓ $(echo "$arch" | tr '[:lower:]' '[:upper:]') $bin saved to: $BUILD_DIR/${bin}-linux-${arch}"
            fi
        done
        rm -rf "$archdir"
    fi
done

# Show results
echo ""
echo "Build complete!"
echo "==============="
echo ""
ls -lh "$BUILD_DIR"/*-linux-*
echo ""

# Verify binaries
echo "Verifying binaries..."
echo "---------------------"
if command -v file &> /dev/null; then
    file "$BUILD_DIR"/*-linux-*
else
    echo "Note: 'file' command not available, skipping binary verification"
fi

echo ""
echo "Binaries are ready in: $BUILD_DIR/"
