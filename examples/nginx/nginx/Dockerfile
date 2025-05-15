FROM openresty/openresty:alpine

# Install development tools for LuaJIT
RUN apk add --no-cache curl

# Create directories for NGINX
RUN mkdir -p /usr/share/nginx/protected /usr/share/nginx/public /usr/local/openresty/nginx/conf

# Copy NGINX configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY magiclink.lua /usr/local/openresty/nginx/conf/magiclink.lua

# Set permissions
RUN chmod -R 755 /usr/share/nginx

# Expose ports
EXPOSE 80

# Command to run
CMD ["nginx", "-g", "daemon off;"]