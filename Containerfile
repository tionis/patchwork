# syntax=docker/dockerfile:1.7

FROM golang:1.24-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    curl \
    git \
    libicu-dev \
    make \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:${PATH}

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
RUN rustup toolchain install nightly-2023-10-05 --profile minimal --component rust-src

WORKDIR /src
COPY . .

RUN make build-all \
    GO_BUILD_TAGS="sqlite_fts5 sqlite_preupdate_hook sqlite_vtable sqlite_icu" \
    SQLITE_CFLAGS="-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_SNAPSHOT -DSQLITE_ENABLE_RBU -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_GEOPOLY" \
    SQLITE_LDFLAGS="-licuuc -licui18n"

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --home /opt/patchwork --create-home --shell /usr/sbin/nologin patchwork

WORKDIR /opt/patchwork

COPY --from=build /src/build/patchwork /opt/patchwork/patchwork
COPY --from=build /src/build/extensions /opt/patchwork/extensions

RUN mkdir -p /var/lib/patchwork && chown -R patchwork:patchwork /var/lib/patchwork /opt/patchwork

ENV PATCHWORK_BIND_ADDR=:8080
ENV PATCHWORK_DATA_DIR=/var/lib/patchwork
ENV PATCHWORK_SQLITE_EXTENSION_CRSQLITE=/opt/patchwork/extensions/crsqlite
ENV PATCHWORK_SQLITE_EXTENSION_VEC=/opt/patchwork/extensions/vec0
ENV PATCHWORK_SQLITE_EXTENSION_SQLEAN=/opt/patchwork/extensions/sqlean
ENV PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR=/opt/patchwork/extensions/sqlean
ENV PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS=ENABLE_FTS5,ENABLE_SESSION,ENABLE_PREUPDATE_HOOK,ENABLE_SNAPSHOT,ENABLE_RBU,ENABLE_RTREE,ENABLE_GEOPOLY,ENABLE_ICU

USER patchwork

EXPOSE 8080
ENTRYPOINT ["/opt/patchwork/patchwork"]
