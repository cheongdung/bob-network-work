# send-arp

### 과제
Sender(Victim)의 ARP table을 변조하라.

### 실행
```
syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
sample : send-arp wlan0 192.168.10.2 192.168.10.1
```

### Demo
Attacker
<video src="https://github.com/user-attachments/assets/750a081a-89e8-4a23-b03f-9ba9cf7b999d"
       controls
       width="100%">
</video>

Victim
<video src="https://github.com/user-attachments/assets/16f5b343-feef-46dd-8423-830ccd7116ed"
       controls
       width="100%">
</video>
![](send-arp-test-victim.mp4)
