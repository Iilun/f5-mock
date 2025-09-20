FROM gcr.io/distroless/base-debian12
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/f5-mock /

ENTRYPOINT ["/f5-mock"]
