#pragma once

#include "peconv.h"

namespace tests {
    // Loads the FlareOn4 Crackme 3, brutforces the key value using a function imported from the crackme and verifies it
    int brutforce_crackme_f4_3();

    //For now this is for manual tests only:
    int deploy_crackme_f4_3(peconv::t_function_resolver* func_resolver);

}; //namespace tests