FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./app .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /server /app/server
EXPOSE 56565
CMD ["/app/server"]