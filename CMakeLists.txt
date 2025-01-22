cmake_minimum_required(VERSION 3.30)
project(ovo C)

set(CMAKE_C_STANDARD 11)

include_directories(/persistent/home/fuqiuluo/etc/env/android-kernel/android15-6.6/common/include)
include_directories(/persistent/home/fuqiuluo/etc/env/android-kernel/android15-6.6/prebuilts/ndk-r26/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include)
include_directories(/persistent/home/fuqiuluo/etc/env/android-kernel/android15-6.6/common/arch/arm64/include)

add_executable(ovo core.c
        mmuhack.c
        mmuhack.h
        kkit.h
        kkit.c
        peekaboo.h
        peekaboo.c)
