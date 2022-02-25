#!/usr/bin/env bash

# https://docs.wxwidgets.org/3.0/
# https://pcapplusplus.github.io/
# https://wiki.wxwidgets.org/Compiling_and_getting_started
# install: pacman -Ss wx-widgets

FILES="switch.cpp"
EXEC="switch"
g++ -std=c++11 -O2 -g -Wall $FILES `wx-config --cxxflags --libs` \
    -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread \
    -I/usr/local/include/pcapplusplus \
    -o $EXEC
