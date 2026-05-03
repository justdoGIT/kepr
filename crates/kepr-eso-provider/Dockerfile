# Multi-stage build for kepr-eso-provider
# Build: cargo build --release (stripped, static)
# Runtime: distroless-static (no shell, no package manager)

FROM rust:1.91-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/kepr-core ./crates/kepr-core
COPY crates/kepr-eso-provider ./crates/kepr-eso-provider
RUN cargo build --release -p kepr-eso-provider \
    && strip target/release/kepr-eso-provider

FROM gcr.io/distroless/static-debian12:nonroot
USER nonroot
COPY --from=build /build/target/release/kepr-eso-provider /kepr-eso-provider
EXPOSE 8080
ENTRYPOINT ["/kepr-eso-provider"]
