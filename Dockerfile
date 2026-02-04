FROM golang:1.25-trixie AS build
COPY / /src
WORKDIR /src
RUN make -B

FROM debian:trixie-slim
COPY --from=build /src/bin/sshoq /bin/sshoq
COPY --from=build /src/bin/sshoq-server /bin/sshoq-server
