##COMPLIE COMMAND:

#for so file:
<ndk_toolchains>-gcc --sysroot=<ndk_toolchains_root_directory>/sysroot -llog -ldl -fPIC -shared -o libthook.so hook.c

#for so_inject executable file:
<ndk_toolchains>-gcc --sysroot=<ndk_toolchains_root_directory>/sysroot -llog -ldl -fPIE -pie -llog -o so_inject so_inject.c

#default hook entry:
`hook_entry`
