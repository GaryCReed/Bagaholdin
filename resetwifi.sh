#!/bin/bash
sudo ifconfig wlan0 down  
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
sudo ifconfig wlan1 down  
sudo iwconfig wlan1 mode managed
sudo ifconfig wlan1 up
sudo systemctl restart NetworkManager.service
