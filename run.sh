#!/bin/bash
sudo ifconfig utun69 192.168.69.1 192.168.69.2 up
ping -c 1 192.168.69.2
