FROM golang:1.24 as builder

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o ./traefik-forward-auth

CMD ["./traefik-forward-auth"]
