FROM golang:1.18
COPY go.mod go.sum /go/tunnel/
WORKDIR /go/tunnel
RUN go mod download
COPY . /go/tunnel
WORKDIR /go/tunnel/server
RUN CGO_ENABLED=0 go build

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /app/
COPY --from=0 /go/tunnel/server/server /app/server
CMD ["/app/server"]  
