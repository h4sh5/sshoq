FROM golang:1.25-trixie AS build
COPY / /src
WORKDIR /src
RUN make

FROM debian:trixie-slim
COPY --from=build /src/bin/client /bin/sshoq
COPY --from=build /src/bin/server /bin/sshoq-server
