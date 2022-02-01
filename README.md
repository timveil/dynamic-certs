# CockroachDB Dynamic Certs Client


## Building the Image
```bash
docker build --no-cache -t timveil/cockroachdb-dynamic-certs:openssl .
```

## Publishing the Image
```bash
docker push timveil/cockroachdb-dynamic-certs:openssl
```

## Running the Image
```bash
docker run -it timveil/cockroachdb-dynamic-certs:openssl
```

running the image with environment variables
```bash
docker run -p 9999:9999 \
    --env NODE_ALTERNATIVE_NAMES='localhost 127.0.0.1' \
    --env CLIENT_USERNAME=myapp \
    --env USE_OPENSSL=true \
    -it timveil/cockroachdb-dynamic-certs:openssl
```