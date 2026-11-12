FROM node:20-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git cmake g++ make openssl libssl-dev zlib1g-dev pkg-config ca-certificates zip \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign /tmp/zsign && cd /tmp/zsign \
 && if [ -f CMakeLists.txt ]; then cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2 && cp build/zsign /usr/local/bin/zsign; \
    else cd build/linux && make clean && make && cp ../../bin/zsign /usr/local/bin/zsign; fi \
 && rm -rf /tmp/zsign

# --- Sideloader: secure Apple account and provisioning backend ---
RUN apt-get update && apt-get install -y --no-install-recommends curl xz-utils libimobiledevice-dev libplist-dev \
 && rm -rf /var/lib/apt/lists/*
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY starksign.d /tmp/starksign.d
RUN ( curl -fsSL https://github.com/ldc-developers/ldc/releases/download/v1.36.0/ldc2-1.36.0-linux-x86_64.tar.xz | tar -xJ -C /opt \
 && export PATH=/opt/ldc2-1.36.0-linux-x86_64/bin:$PATH \
 && git clone --depth 1 https://github.com/Dadoum/Sideloader /opt/sideloader && cd /opt/sideloader \
 && cp /tmp/starksign.d frontends/cli/source/starksign.d \
 && sed -i '/^import tool;$/a import starksign;' frontends/cli/source/cli_frontend.d \
 && sed -i '/(ToolCommand cmd) => cmd(),/a\                (StarkSignCommand cmd) => cmd(),' frontends/cli/source/cli_frontend.d \
 && sed -i 's/ToolCommand, VersionCommand/ToolCommand, StarkSignCommand, VersionCommand/' frontends/cli/source/cli_frontend.d \
 && sed -i 's/sslSetVerifyPeer(false)/sslSetVerifyPeer(true)/g' source/server/appleaccount.d \
 && sed -i 's/sslSetVerifyPeer(false)/sslSetVerifyPeer(true)/g' source/app/package.d \
 && cd frontends/cli \
 && dub build -b release --compiler=ldc2 2>&1 | tee /tmp/sideloader-build.log \
 && cp ../../bin/sideloader /usr/local/bin/sideloader ) || (echo "SIDELOADER_BUILD_FAILED" && exit 1)

WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
CMD ["node","server.js"]
