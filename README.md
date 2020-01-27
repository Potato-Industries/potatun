
# potatun

An experimental packet tunnelling bind shell using obscure techniques to evade IDS/IPS.

- TCP/UDP (source port encoding)
- ICMP (payload)
- SCTP (chunkdata)
- IPSEC (esp)
- Netflow (V5, netflow record source port encoding)
- Netbios (NBNSQueryRequest, question_name)

NOTE: 
- Data encryption is used where applicable.
- Invalid use of protocols should be detected by robust SIEM. 

**Requirements**

- python3
- scapy

**Usage**

```
root@kali:/opt/potatun# python3 potatun.py -h
usage: potatun.py [-h] [-i I] [-t T] [-m M]

potatun - an experimental packet tunnelling bind shell.

optional arguments:
  -h, --help  show this help message and exit
  -i I        send interface (eth0)
  -t T        send ip:port (10.10.10.1:443)
  -m M        tunnel mode (udp-c/udp-s, tcp-c/tcp-s, icmp-c/icmp-s,
              sctp-c/sctp-s, ipsec-c/ipsec-s, netflow-c/netflow-s, netbios-c/netbios-s)
```
**Netflow (v5 record source port encoding)**

<img width="1578" alt="Screenshot 2019-12-15 at 07 02 33" src="https://user-images.githubusercontent.com/56988989/70859301-52a60480-1f09-11ea-8018-22dfb603fddf.png">

**UDP (source port encoding)**

<img width="1658" alt="Screenshot 2019-12-13 at 06 14 07" src="https://user-images.githubusercontent.com/56988989/70773805-58b4ad80-1d70-11ea-88c4-5e86867989a6.png">

**TCP (source port encoding)**

<img width="1658" alt="Screenshot 2019-12-13 at 06 30 28" src="https://user-images.githubusercontent.com/56988989/70774625-b8ac5380-1d72-11ea-82cb-7ed2c4a6e567.png">

**SCTP (chunkdata)**

<img width="1583" alt="Screenshot 2019-12-15 at 02 18 17" src="https://user-images.githubusercontent.com/56988989/70857201-14e1b580-1ee2-11ea-8a34-d17fcb0b13f7.png">

**ICMP (payload)** 

<img width="1664" alt="Screenshot 2019-12-13 at 06 36 18" src="https://user-images.githubusercontent.com/56988989/70774920-e396a780-1d72-11ea-96fa-7a6e1089672e.png">

**IPSEC (esp)** 

<img width="1578" alt="Screenshot 2019-12-15 at 03 46 41" src="https://user-images.githubusercontent.com/56988989/70857854-1618df80-1eee-11ea-807f-e78593d49f67.png">

**NetBIOS (NBNSQueryRequest)**

<img width="1582" alt="Screenshot 2019-12-16 at 11 34 42" src="https://user-images.githubusercontent.com/56988989/70904113-7c8a2480-1ff8-11ea-89d0-159aa327970b.png">

**Disclaimer**

Don't use this script in real-life, bind shells are sketchy, it's purely for research/experimentation, there are a ton of other safe/stable open source options. 


Enjoy~

