# CockroachDB Dynamic Certs Client


## Building the Image
```bash
docker build --no-cache --platform linux/arm64 -t timveil/cockroachdb-dynamic-certs:latest .
```

## Publishing the Image
```bash
docker push timveil/cockroachdb-dynamic-certs:latest
```

## Running the Image
```bash
docker run -it timveil/cockroachdb-dynamic-certs:latest
```

running the image with environment variables
```bash
docker run -p 9999:9999 \
    --env NODE_ALTERNATIVE_NAMES=localhost \
    -it timveil/cockroachdb-dynamic-certs:latest
```