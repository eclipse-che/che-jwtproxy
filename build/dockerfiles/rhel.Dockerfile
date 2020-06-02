# Copyright (c) 2019 Red Hat, Inc.
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
#
# Contributors:
#   Red Hat, Inc. - initial API and implementation
#

# UPSTREAM: use devtools/go/-toolset-rhel7 image so we're not required to authenticate with registry.redhat.io
# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/devtools/go-toolset-rhel7
FROM registry.access.redhat.com/devtools/go-toolset-rhel7:1.12.12-3.1582636125 as builder
ENV PATH=/opt/rh/go-toolset-1.12/root/usr/bin:$PATH
# DOWNSTREAM: use rhel8/go-toolset; no path modification needed
# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/rhel8/go-toolset
# FROM registry.redhat.io/rhel8/go-toolset:1.12.8-45 as builder

ENV GOPATH=/go/
USER root
WORKDIR /go/src/github.com/eclipse/che-jwtproxy/
COPY . /go/src/github.com/eclipse/che-jwtproxy/
RUN adduser appuser && \
    CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -a -installsuffix cgo -o jwtproxy cmd/jwtproxy/main.go

# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/ubi8-minimal
FROM registry.access.redhat.com/ubi8-minimal:8.1-409
USER appuser
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/src/github.com/eclipse/che-jwtproxy/jwtproxy /usr/local/bin
ENTRYPOINT ["jwtproxy"]
# The JWT proxy needs 2 things:
# * the location of the configuration file supplied as an argument:
#   `-config <location/of/the/config.yaml>`
# * The XDG_CONFIG_HOME environment variable pointing to a directory where to store auth keys
# CMD ["-config", "/che-jwtproxy-config/config.yaml"]

# append Brew metadata here
