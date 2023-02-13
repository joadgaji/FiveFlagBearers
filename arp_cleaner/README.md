# ARP CLEARNER
This package send the right ip address in a controlled environment. The intentions is to modify dabase file with the ip and mac relations that we don't want to be spoofed. 

The file also needs one key=valye record with the braodcast of that subnet 

The binary needs as an input the interface

### Example

```
make
```
```
.arp_cleaner --interface 192.168.1.255
```
