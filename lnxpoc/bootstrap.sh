#!/bin/sh

echo "[*] Installing build and debug dependencies."
apt-get update && apt-get install -y build-essential \
                   automake \
                   gdb \
                   gdbserver \
                   ghostscript \
                   systemd

echo "[*] Creating nginx user if it does not exist."
useradd -m nginx 2> /dev/null

export NGINX_HOME=/home/nginx

cd /vagrant

echo "[*] Copying build files to VM."
cp -r nginx-release-1.4.0 pcre-8.40 zlib-1.2.11 $NGINX_HOME

echo "[*] Copying nginx.service to VM."
cp nginx.service /lib/systemd/system/nginx.service

if [ ! -e /usr/sbin/nginx ]; then

    echo "[*] Building nginx."
    cd $NGINX_HOME/nginx-release-1.4.0

    ./auto/configure --prefix=/opt/nginx \
                     --sbin-path=/usr/sbin/nginx \
                     --conf-path=/opt/nginx/nginx.conf \
                     --pid-path=/var/run/nginx.pid \
                     --lock-path=/var/run/nginx.lock \
                     --with-zlib=../zlib-1.2.11 \
                     --with-pcre=../pcre-8.40

    make && make install

fi

cd /vagrant

echo "[*] Copying configuration file."
cp nginx.conf /opt/nginx/nginx.conf

echo "[*] Copying debugger configuration files to home directory."
cp -rT gdbconfig $HOME

echo "[*] Copying compiled binaries to shared directory for debugging."
cp -r $NGINX_HOME/nginx-release-1.4.0/objs /vagrant/nginx-release-1.4.0

echo "[*] Launching nginx."
systemctl enable nginx.service && systemctl start nginx.service
