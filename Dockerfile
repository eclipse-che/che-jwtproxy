#
# Copyright (c) 2012-2018 Red Hat, Inc.
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
#
# Contributors:
#   Red Hat, Inc. - initial API and implementation
#

FROM golang:1.12-alpine3.9 as builder
RUN apk add --no-cache ca-certificates
RUN adduser -D -g '' appuser
WORKDIR /go/src/github.com/eclipse/che-jwtproxy/
COPY . /go/src/github.com/eclipse/che-jwtproxy/
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -a -installsuffix cgo -o jwtproxy cmd/jwtproxy/main.go

FROM alpine:3.9
USER appuser
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/github.com/eclipse/che-jwtproxy/jwtproxy /usr/local/bin
ENTRYPOINT ["jwtproxy"]
# The JWT proxy needs 2 things:
# * the location of the configuration file supplied as an argument:
#   `-config <location/of/the/config.yaml>`
# * The XDG_CONFIG_HOME environment variable pointing to a directory where to store auth keys
# CMD ["-config", "/che-jwtproxy-config/config.yaml"]
