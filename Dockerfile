FROM docker.io/rust:1-alpine as build

RUN apk add --no-cache musl-dev 
WORKDIR /usr/src/vip_tracerouter
COPY Cargo.toml Cargo.lock rust-toolchain.toml .
COPY src ./src
RUN cargo build --release


# Final Container
FROM scratch as final
COPY --from=build /usr/src/vip_tracerouter/target/release/vip_tracerouter /vip_tracerouter
ENTRYPOINT ["/vip_tracerouter"]

