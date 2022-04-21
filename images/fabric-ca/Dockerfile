#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine as builder
ARG GO_LDFLAGS
ARG GO_TAGS

RUN sed -i "s?dl-cdn.alpinelinux.org?mirrors.aliyun.com?g" /etc/apk/repositories \
	&& apk add --no-cache \
	gcc \
	binutils-gold \
	git \
	musl-dev;

ADD . /build/fabric-ca
WORKDIR /build/fabric-ca
RUN go env -w GOPROXY=https://goproxy.cn,direct \
    && go env -w GOPRIVATE=gitee.com/zhaochuninhefei \
	&& go install -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	gitee.com/zhaochuninhefei/fabric-ca-gm/cmd/fabric-ca-server \
	&& go install -tags "${GO_TAGS}" -ldflags "${GO_LDFLAGS}" \
	gitee.com/zhaochuninhefei/fabric-ca-gm/cmd/fabric-ca-client


FROM alpine:${ALPINE_VER}
RUN sed -i "s?dl-cdn.alpinelinux.org?mirrors.aliyun.com?g" /etc/apk/repositories \
	&& apk add --no-cache tzdata
ENV FABRIC_CA_HOME /etc/hyperledger/fabric-ca-server
COPY --from=builder /go/bin /usr/local/bin
EXPOSE 7054
CMD fabric-ca-server start -b admin:adminpw
