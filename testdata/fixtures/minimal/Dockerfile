# syntax=docker/dockerfile:1
FROM golang:1.22@sha256:1111111111111111111111111111111111111111111111111111111111111 AS builder
WORKDIR /src
COPY . .
RUN go build -o /out/app ./cmd/app

FROM builder AS test
RUN go test ./...

FROM gcr.io/distroless/static-debian12:latest
COPY --from=builder /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
