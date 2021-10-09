# Virtual IP addresses discoverable via traceroute
| Some people may ask *Warum?* I say *darum!*

This project is a little silly and no one should every use it to properly provide some sort of usable services on these
virtual IP addresses but come one it's free IP addresses! Who can say no to **that**?!? 

## What does this do?
This program makes it look like there are a bunch of computers that respond to pings in a virtual private network 
connected to the running computer.
It also spoofs routing information in a way that makes it look like packets are routed through all these virtual
computers.

Here is what it looks like when _traceroute_ is run against one of these virtual ip addresses:
```shell                                                                                                                                   0
traceroute to 10::5 (10::f), 30 hops max, 80 byte packets
 1  <my-hostname> (10::1)  0.218 ms  0.230 ms  0.246 ms
 2  10::2 (10::2)  0.264 ms  0.280 ms  0.290 ms
 3  10::3 (10::3)  0.306 ms  0.323 ms  0.341 ms
 4  10::4 (10::4)  0.357 ms  0.366 ms  0.370 ms
 5  10::5 (10::5)  0.373 ms  0.376 ms  0.380 ms
```

## Why is this useful?
**It is not.**

But it is quite fun.
For example, I use it in conjunction with reverse DNS records to output my CV via traceroute.
You can try it yourself by probing [cv6.finn-thorben.me](./) (if you can route IPv6 traffic that is).
