Add iproute2mac package to run map an ip with a tun interface.

```bash
brew install iproute2mac
```

After the tun interface is created, we assign a static ip to it

```bash
sudo ifconfig utun69 192.168.69.1 192.168.69.2 up
```


Now we can ping the ip

```bash
ping -c 3 192.168.69.2
```
