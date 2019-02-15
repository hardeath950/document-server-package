## Increase this if you want to upload large attachments
client_max_body_size 100m;

gzip on;
gzip_vary on;
gzip_types  text/plain
            text/xml
            text/css
            text/csv
            font/ttf
            application/xml
            application/javascript
            application/x-javascript
            application/json
            application/octet-stream
            application/x-font-ttf
            application/rtf;

access_log off;
error_log M4_NGINX_LOG/nginx.error.log;