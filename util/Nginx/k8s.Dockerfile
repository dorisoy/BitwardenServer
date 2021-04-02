FROM nginx:1.18

LABEL com.bitwarden.product="bitwarden"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx
COPY proxy.conf /etc/nginx
COPY mime.types /etc/nginx
COPY security-headers.conf /etc/nginx
COPY security-headers-ssl.conf /etc/nginx

RUN mkdir -p /var/run/nginx
RUN touch /var/run/nginx/nginx.pid
RUN chown -R nobody:nogroup /var/run/nginx
RUN chown -R nobody:nogroup /var/cache/nginx
RUN chown -R nobody:nogroup /var/log/nginx

USER nobody:nogroup

EXPOSE 8080
EXPOSE 8443

HEALTHCHECK CMD curl --insecure -Lfs https://localhost:8443/alive || curl -Lfs http://localhost:8080/alive || exit 1

CMD ["nginx", "-g", "daemon off;"]
