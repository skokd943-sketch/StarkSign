FROM node:20-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git cmake g++ make libssl-dev zlib1g-dev pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign /tmp/zsign && cd /tmp/zsign \
 && if [ -f CMakeLists.txt ]; then cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2 && cp build/zsign /usr/local/bin/zsign; \
    else cd build/linux && make clean && make && cp ../../bin/zsign /usr/local/bin/zsign; fi \
 && rm -rf /tmp/zsign
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
CMD ["node","server.js"]
