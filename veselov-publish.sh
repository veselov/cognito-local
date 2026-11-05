  Log in: docker login
  Create a builder for this:
  docker buildx create --name cognito-local-builder --driver docker-container --use


    ( set -e
    test -z "$(git status --porcelain -- src package.json yarn.lock Dockerfile)" || { echo "uncommitted changes" >&2; exit 1; }
    tag=$(git describe --tags --exact-match)
    docker buildx build --builder cognito-local-builder \
    --platform linux/amd64,linux/arm64 \
    --label org.opencontainers.image.revision=$(git rev-parse HEAD) \
    -t excelforeveselov/cognito-local:${tag#v} --push . )


