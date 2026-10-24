# The end-to-end test image. The build context is e2e/, and the dbfence
# binary is built beforehand with the repository's toolchain:
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o e2e/dbfence .
FROM alpine:3.22

RUN apk add --no-cache bash ca-certificates

# The CA bundle of Amazon RDS, for tls = "verify-full" on the aws targets.
ADD --chmod=644 https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /etc/dbfence-e2e/rds-global-bundle.pem
ENV DBFENCE_E2E_TLS_CA_FILE=/etc/dbfence-e2e/rds-global-bundle.pem

COPY --chmod=755 dbfence /usr/local/bin/dbfence
COPY --chmod=755 run.sh /opt/dbfence-e2e/run.sh
COPY scenario /opt/dbfence-e2e/scenario
COPY targets /opt/dbfence-e2e/targets

USER 65534:65534
ENTRYPOINT ["/opt/dbfence-e2e/run.sh"]
