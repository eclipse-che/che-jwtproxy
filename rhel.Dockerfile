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

# UPSTREAM: use devtools/go-toolset-rhel7 image so we're not required to authenticate with registry.redhat.io
# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/rhel8/go-toolset
FROM registry.access.redhat.com/devtools/go-toolset-rhel7:1.11.13-11.1571302666 as builder
ENV PATH=/opt/rh/go-toolset-1.11/root/usr/bin:$PATH

# DOWNSTREAM: use rhel8/go-toolset; no path modification needed
# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/rhel8/go-toolset
# FROM registry.redhat.io/rhel8/go-toolset:1.12.8-11 as builder

ENV GOPATH=/go/
USER root
WORKDIR /go/src/github.com/eclipse/che-jwtproxy/
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -a -installsuffix cgo -o jwtproxy cmd/jwtproxy/main.go

# https://access.redhat.com/containers/?tab=tags#/registry.access.redhat.com/ubi8-minimal
FROM registry.access.redhat.com/ubi8-minimal:8.1-279

ENV XDG_CONFIG_HOME=/config/
VOLUME /config
COPY --from=builder /go/src/github.com/eclipse/che-jwtproxy/jwtproxy /usr/local/bin
ENTRYPOINT ["jwtproxy"]
CMD ["-config", "/config/config.yaml"]

# append Brew metadata here
