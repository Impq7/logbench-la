# 官方引擎 agent 镜像：在 agentdojo 基础上补 tcpdump/iproute2，用于 N 模态网卡抓包。
FROM logbench-native-dev:82f7911781dc78ba
USER root
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iproute2 curl && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
