# SETUP

- Install Vcpkg:  
`git clone https://github.com/microsoft/vcpkg.git`  
`cd vcpkg`  
`./bootstrap-vcpkg.sh  -disableMetrics`  
Change `-DCMAKE_TOOLCHAIN_FILE` in `build.sh` to point to yours vcpkg installation  

# BUILD

- Build using `./build.sh`

# RUN

- Run using `sudo ./out/rumi -e -P myprocessname`
