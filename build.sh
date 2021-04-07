#!/bin/sh

 rm *.o ; g++ -std=c++2a -c *.cpp; g++ -std=c++2a -o columbo *.o
