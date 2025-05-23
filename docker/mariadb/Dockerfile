FROM mariadb:11

# 安裝 mysql CLI 工具
RUN apt-get update && \
    apt-get install -y mariadb-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 保留與官方一致的 entrypoint
CMD ["mysqld"]
