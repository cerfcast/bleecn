FROM rust:1.74

WORKDIR /usr/src/cerf-bleecn
COPY . .

RUN cargo install --path .

CMD ["cerf-bleecn"]
