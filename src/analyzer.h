#pragma once
#include "common.h"

class Analyzer
{
public:
    virtual void onPacketReceived(std::function<void(const int&)>) = 0;



};
