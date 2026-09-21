# ReasonGate in front of the official filesystem MCP server, as one stdio server.
#
#   docker build -t reasongate-mcp .
#   docker run -i --rm -v "$PWD/notes:/data" reasongate-mcp
#
# The gateway launches @modelcontextprotocol/server-filesystem on /data, forwards
# every MCP message, drafts a policy per tool from the server's own schemas and
# blocks a tools/call whose destination or content came from an untrusted tool
# result. Swap the CMD to put it in front of any other stdio server.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @modelcontextprotocol/server-filesystem \
 && pip3 install --no-cache-dir --break-system-packages reasongate \
 && mkdir -p /data

VOLUME ["/data"]

# stdout carries only MCP messages; the gateway logs its decisions on stderr.
ENTRYPOINT ["reasongate-mcp", "--"]
CMD ["mcp-server-filesystem", "/data"]
