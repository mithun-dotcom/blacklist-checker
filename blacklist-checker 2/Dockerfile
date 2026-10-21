FROM php:8.3-apache

# Serve ./public as the web root; ./src stays outside it.
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
# Render sets PORT at runtime; default to 10000 (Render's default) otherwise.
ENV PORT=10000
RUN sed -ri 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri 's!Listen 80!Listen ${PORT}!' /etc/apache2/ports.conf \
 && sed -ri 's!<VirtualHost \*:80>!<VirtualHost *:${PORT}>!' /etc/apache2/sites-available/000-default.conf

COPY src/ /var/www/html/src/
COPY public/ /var/www/html/public/
