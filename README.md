
# potatun

an experimental packet tunnelling bind shell.

- TCP/UDP (source port)
- ICMP (payload)

**Usage**

```
root@kali:/opt/potatun# python3 potatun.py 
usage: potatun.py [-h] [-i I] [-t T] [-m M]

potatun - an experimental packet tunnelling bind shell.

optional arguments:
  -h, --help  show this help message and exit
  -i I        send interface (e.g. eth0)
  -t T        send ip:port (e.g. 10.10.10.1:443)
  -m M        tunnel mode (udp-c/udp-s or tcp-c/tcp-s or icmp-c/icmp-s)

```

**UDP**

<img width="1658" alt="Screenshot 2019-12-13 at 06 14 07" src="https://user-images.githubusercontent.com/56988989/70773805-58b4ad80-1d70-11ea-88c4-5e86867989a6.png">

**TCP**

<img width="1658" alt="Screenshot 2019-12-13 at 06 30 28" src="https://user-images.githubusercontent.com/56988989/70774625-b8ac5380-1d72-11ea-82cb-7ed2c4a6e567.png">

**ICMP** (control)

<img width="1664" alt="Screenshot 2019-12-13 at 06 36 18" src="https://user-images.githubusercontent.com/56988989/70774920-e396a780-1d72-11ea-96fa-7a6e1089672e.png">

**Issues**
- You will have noticed that some characters are missing in the response output in the screenshots ('rot' instead of 'root'). This is due to a workaround that is required for localhost to localhost connections whereby Scapy is unable to identify which packets are outbound or inbound. This workaround is disabled in the script. This does not affect host to host connections on separate boxes.      

**Findings**   
- wow this is pretty noisey. (potentially for TCP, maybe less noticable for UDP, you could try going slow! increase time.sleep durations between send operations)
- ok.. now it's super slow. (yes! slow is good! stay covert.) 


**Disclaimer**

Don't use this script in real-life, bind shells are sketchy, it's purely for research/experimentation, there are a ton of other safe/stable open source options. 


Enjoy~

