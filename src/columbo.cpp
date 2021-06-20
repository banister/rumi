#include "common.h"
#include "engine.h"
#if defined(CMB_MACOS)
#include "mac_engine.h"
#endif

int main(int argc, char** argv)
{
    std::unique_ptr<Engine> engine;

#if defined(CMB_MACOS)
    engine = std::make_unique<MacEngine>();
#endif

    try
    {
        engine->start(argc, argv);
    }
    catch(const SystemError& ex)
    {
        std::cerr << "Error: " << ex.what();
        if(ex.code() == EACCES || ex.code() == EPERM)
            std::cerr << " - Try running as root.";

        std::cerr << std::endl;
        return 1;
    }
    catch(const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

