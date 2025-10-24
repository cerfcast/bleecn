FROM rust:1.82 AS builder

WORKDIR /usr/src/cerf-bleecn
COPY . .

RUN cargo install --path .

FROM debian:trixie-slim
#RUN apt-get update && apt-get install -y libssl-dev  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/cerf-bleecn /usr/local/bin/cerf-bleecn

CMD ["cerf-bleecn"]
