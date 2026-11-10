FROM php:7.1-apache
# CVE-2026-111497: libbrotli1 must be >= 1.0.9-2ubuntu0.1 (Ubuntu jammy-security).
# php:7.1-apache is Debian 10 (glibc 2.28). The published jammy binary needs
# libc6 >= 2.29, so rebuild that security update against this image's libc.
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    cp /etc/apt/sources.list /tmp/sources.list.bak; \
    printf '%s\n' \
      'deb http://archive.debian.org/debian buster main' \
      'deb http://archive.debian.org/debian-security buster/updates main' \
      > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive-buster; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-upgrade cmake; \
    mkdir -p /tmp/brotli-src; \
    cd /tmp/brotli-src; \
    curl -fsSL -o brotli_1.0.9.orig.tar.gz http://security.ubuntu.com/ubuntu/pool/main/b/brotli/brotli_1.0.9.orig.tar.gz; \
    curl -fsSL -o brotli_1.0.9-2ubuntu0.1.debian.tar.xz http://security.ubuntu.com/ubuntu/pool/main/b/brotli/brotli_1.0.9-2ubuntu0.1.debian.tar.xz; \
    echo 'f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46  brotli_1.0.9.orig.tar.gz' | sha256sum -c -; \
    echo 'd40552e0699ccdde6d70e41c204d53d5152e0987dc4f9c41b5f5c03a0543bcba  brotli_1.0.9-2ubuntu0.1.debian.tar.xz' | sha256sum -c -; \
    tar -xzf brotli_1.0.9.orig.tar.gz; \
    tar -xJf brotli_1.0.9-2ubuntu0.1.debian.tar.xz -C brotli-1.0.9; \
    cd brotli-1.0.9; \
    while IFS= read -r patchfile; do \
      [ -n "${patchfile}" ] || continue; \
      patch -p1 < "debian/patches/${patchfile}"; \
    done < debian/patches/series; \
    triplet="$(gcc -dumpmachine)"; \
    mkdir build && cd build; \
    cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_INSTALL_LIBDIR="lib/${triplet}" \
      -DBUILD_SHARED_LIBS=ON; \
    make -j"$(nproc)"; \
    printf 'brotli-cve-2026-111497\n' > /tmp/brotli-roundtrip.in; \
    LD_LIBRARY_PATH="$PWD" ./brotli /tmp/brotli-roundtrip.in -o /tmp/brotli-roundtrip.br; \
    LD_LIBRARY_PATH="$PWD" ./brotli -d /tmp/brotli-roundtrip.br -o /tmp/brotli-roundtrip.out; \
    cmp /tmp/brotli-roundtrip.in /tmp/brotli-roundtrip.out; \
    rm -rf /tmp/libbrotli-root; \
    mkdir -p "/tmp/libbrotli-root/usr/lib/${triplet}" /tmp/libbrotli-root/DEBIAN /tmp/libbrotli-root/usr/share/doc/libbrotli1; \
    cp -a libbrotlicommon.so.1.0.9 libbrotlidec.so.1.0.9 libbrotlienc.so.1.0.9 "/tmp/libbrotli-root/usr/lib/${triplet}/"; \
    ln -s libbrotlicommon.so.1.0.9 "/tmp/libbrotli-root/usr/lib/${triplet}/libbrotlicommon.so.1"; \
    ln -s libbrotlidec.so.1.0.9 "/tmp/libbrotli-root/usr/lib/${triplet}/libbrotlidec.so.1"; \
    ln -s libbrotlienc.so.1.0.9 "/tmp/libbrotli-root/usr/lib/${triplet}/libbrotlienc.so.1"; \
    cp ../debian/copyright /tmp/libbrotli-root/usr/share/doc/libbrotli1/copyright; \
    arch="$(dpkg --print-architecture)"; \
    size="$(du -sk /tmp/libbrotli-root/usr | awk '{print $1}')"; \
    { \
      echo 'Package: libbrotli1'; \
      echo 'Source: brotli'; \
      echo 'Version: 1.0.9-2ubuntu0.1'; \
      echo "Architecture: ${arch}"; \
      echo 'Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>'; \
      echo "Installed-Size: ${size}"; \
      echo 'Depends: libc6 (>= 2.14)'; \
      echo 'Section: libs'; \
      echo 'Priority: optional'; \
      echo 'Multi-Arch: same'; \
      echo 'Homepage: https://github.com/google/brotli'; \
      echo 'Description: library implementing brotli encoder and decoder (shared libraries)'; \
      echo ' Rebuilt from Ubuntu jammy-security 1.0.9-2ubuntu0.1 (CVE-2026-111497)'; \
      echo ' against this image libc. The jammy binary itself needs libc6 >= 2.29.'; \
    } > /tmp/libbrotli-root/DEBIAN/control; \
    printf '%s\n' \
      'libbrotlicommon 1 libbrotli1 (>= 1.0.9)' \
      'libbrotlidec 1 libbrotli1 (>= 1.0.9)' \
      'libbrotlienc 1 libbrotli1 (>= 1.0.9)' \
      > /tmp/libbrotli-root/DEBIAN/shlibs; \
    printf '%s\n' '# ldconfig' 'activate-noawait ldconfig' > /tmp/libbrotli-root/DEBIAN/triggers; \
    dpkg-deb -b /tmp/libbrotli-root /tmp/libbrotli1.deb; \
    dpkg -i /tmp/libbrotli1.deb; \
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libbrotli1)" ge '1.0.9-2ubuntu0.1'; \
    test ! -e "/usr/lib/${triplet}/libbrotlidec.so.1.0.7"; \
    apt-get purge -y cmake cmake-data libarchive13 libjsoncpp1 librhash0 libuv1; \
    rm -rf /var/lib/apt/lists/* /tmp/brotli-src /tmp/libbrotli-root /tmp/libbrotli1.deb \
      /tmp/brotli-roundtrip.in /tmp/brotli-roundtrip.br /tmp/brotli-roundtrip.out \
      /etc/apt/apt.conf.d/99archive-buster; \
    mv /tmp/sources.list.bak /etc/apt/sources.list
RUN docker-php-ext-install mysqli
