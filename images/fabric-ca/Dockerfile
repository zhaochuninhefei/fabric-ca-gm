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
ENV TIME_ZONE=Asia/Shanghai LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8 FABRIC_CA_HOME=/etc/hyperledger/fabric-ca-server BOOTSTRAP_USER_PASS=admin:adminpw
COPY --from=builder /go/bin /usr/local/bin
RUN \
	sed -i "s?dl-cdn.alpinelinux.org?mirrors.aliyun.com?g" /etc/apk/repositories \
	&& apk add --no-cache tzdata \
	&& echo "${TIME_ZONE}" > /etc/timezone \
	&& ln -sf /usr/share/zoneinfo/${TIME_ZONE} /etc/localtime \
	&& mkdir -p /etc/hyperledger/fabric-ca-client/tls-root-cert \
	&& echo 'fabric-ca-server start -b ${BOOTSTRAP_USER_PASS} -d' > /usr/local/bin/start_ca.sh \
	&& chmod +x /usr/local/bin/start_ca.sh
EXPOSE 7054
# CMD fabric-ca-server start -b ${BOOTSTRAP_USER_PASS}
CMD /usr/local/bin/start_ca.sh
