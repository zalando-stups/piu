FROM registry.opensource.zalan.do/stups/python AS builder
ARG VERSION
RUN apt-get update && \
    apt-get install -q -y python3-pip && \
    pip3 install -U setuptools
COPY . /build
WORKDIR /build
RUN sed -i "s/__version__ = .*/__version__ = \"${VERSION}\"/" */__init__.py
RUN python3 setup.py sdist bdist_wheel
RUN tar xf /build/dist/*.tar.gz -C /tmp && cat /tmp/stups-piu*/PKG-INFO | egrep '^Version: ' | sed 's/Version: //' > /build/dist/.version

FROM pierone.stups.zalan.do/teapot/python-cdp-release:latest
COPY --from=builder /build/dist /pydist
