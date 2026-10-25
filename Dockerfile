# NetPulse Zeek collector: official Zeek image + JA3/JA4 fingerprint packages.
FROM zeek/zeek:latest

USER root

# JA4 is a compiled plugin: it needs a compiler and CMake to build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake g++ make libpcap-dev libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

RUN zkg install --force --skiptests zeek/foxio/ja4 \
 && zkg install --force --skiptests zeek/salesforce/ja3

# JA4 loads itself as a compiled plugin. Loading its script copy as well
# ("ja4-zeek-scripts") makes Zeek exit with "FINGERPRINT::Info has already
# been declared". Keep only JA3 in the package load list.
RUN printf '# managed by NetPulse\n@load ./ja3\n' \
      > /usr/local/zeek/share/zeek/site/packages/packages.zeek

# The stock local.zeek has "@load packages" commented out, so JA3 would never load.
RUN echo '@load packages' >> /usr/local/zeek/share/zeek/site/local.zeek
