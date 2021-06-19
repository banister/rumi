#pragma once

#include "common.h"
#include "engine.h"
#include "bpf_device.h"

class MacEngine : public Engine
{
protected:
    virtual void showTraffic(const Config &config) override;
    virtual void showConnections(const Config &config) override;
    virtual void showExec(const Config &config) override;
};
