FROM nginx:alpine

# nginx:alpine ships without openssl, and the entrypoint needs it to hash
# DOCS_PASSWORD. Installing it at build time keeps the running container
# air-gapped, which is a hard requirement for this project.
RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
