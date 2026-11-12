FROM node:20-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git cmake g++ make libssl-dev zlib1g-dev pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign /tmp/zsign && cd /tmp/zsign \
 && if [ -f CMakeLists.txt ]; then cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2 && cp build/zsign /usr/local/bin/zsign; \
    else cd build/linux && make clean && make && cp ../../bin/zsign /usr/local/bin/zsign; fi \
 && rm -rf /tmp/zsign

# --- РАЗВЕДКА: Sideloader (вход по Apple ID). Если не соберётся, сервер всё равно работает ---
RUN apt-get update && (apt-get install -y --no-install-recommends curl xz-utils libimobiledevice-dev libplist-dev || echo "SIDELOADER_DEPS_FAILED") \
 && rm -rf /var/lib/apt/lists/*
RUN ( curl -fsSL https://github.com/ldc-developers/ldc/releases/download/v1.36.0/ldc2-1.36.0-linux-x86_64.tar.xz | tar -xJ -C /opt \
 && export PATH=/opt/ldc2-1.36.0-linux-x86_64/bin:$PATH \
 && git clone --depth 1 https://github.com/Dadoum/Sideloader /opt/sideloader && cd /opt/sideloader \
 && echo "SIDELOADER_CONFIGS:" && dub build --print-configs --compiler=ldc2 2>&1 | tail -20 \
 && CFG=$(dub build --print-configs --compiler=ldc2 2>/dev/null | grep -i cli | head -1 | sed 's/^ *//; s/ .*//') \
 && echo "SIDELOADER_CFG=$CFG" \
 && dub build -b release --compiler=ldc2 --config="$CFG" 2>&1 | tail -60 \
 && ls -la bin && cp bin/sideloader /usr/local/bin/sideloader ) || echo "SIDELOADER_BUILD_FAILED"

WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
CMD ["node","server.js"]
