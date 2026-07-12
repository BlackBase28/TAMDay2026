# Changelog

## 2.7.5

- Fixed deployment cleanup for legacy httpd config name `/etc/httpd/conf.d/cve-radar.conf`.
- Install/update scripts now disable the old config if present, so httpd uses only `/etc/httpd/conf.d/kernel-cve-radar.conf`.
- Confirmed normal and maintenance httpd configs write to standard RHEL logs: `/var/log/httpd/access_log` and `/var/log/httpd/error_log`.

## 2.7.4

- httpd logs changed to standard RHEL paths: `/var/log/httpd/access_log` and `/var/log/httpd/error_log`.
- DDoS demo guidance adjusted to maintenance-page isolation scenarios.
