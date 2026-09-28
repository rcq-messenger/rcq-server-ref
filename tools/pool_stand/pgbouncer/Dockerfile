# PgBouncer for the local pool stand (tools/pool_stand/README.md). Local only.
FROM alpine:latest
RUN apk add --no-cache pgbouncer && adduser -D -H pgbouncer
COPY pgbouncer.ini userlist.txt /etc/pgbouncer/
RUN chown -R pgbouncer /etc/pgbouncer
USER pgbouncer
EXPOSE 6432
CMD ["pgbouncer", "/etc/pgbouncer/pgbouncer.ini"]
