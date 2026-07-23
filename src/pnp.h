#pragma once
#include "config.h"
#include <vector>
#include <string>

struct EnumCom {
    std::string com;       // "COM44"
    std::string parent;    // USB\VID_xxxx&PID_yyyy&MI_00\7&abcd&0&0000
};

std::vector<EnumCom> enumerate_com_ports();
std::string resolve_com(const SerialCfg& cfg, const std::vector<EnumCom>& devs);
