#!/bin/sh

 rm *.o ; g++ -std=c++2a -c port_finder.cpp; g++ -std=c++2a -c columbo.cpp; g++ -std=c++2a -o columbo columbo.o port_finder.o
