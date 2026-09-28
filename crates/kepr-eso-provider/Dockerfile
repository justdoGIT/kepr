# Multi-stage build for kepr-eso-provider
# Build: cargo build --release (stripped, static)
# Runtime: distroless-static (no shell, no package manager)

FROM rust:1.91-alpine@sha256:45c1c35cd364b8055e9e86f8ecd3e8c874b2dcb658d8a4f94b5d111aa0d651a2 AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/kepr-core ./crates/kepr-core
COPY crates/kepr-eso-provider ./crates/kepr-eso-provider
RUN cargo build --release -p kepr-eso-provider \
    && strip target/release/kepr-eso-provider

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
USER nonroot
COPY --from=build /build/target/release/kepr-eso-provider /kepr-eso-provider
EXPOSE 8080
ENTRYPOINT ["/kepr-eso-provider"]
