/**
适用于Thumb指令集的Native函数INLINE HOOK
Hook 函数入口点： hook_entry
参数：0 - 直接返回Hook函数
     1 - 调用Hook函数后，返回原函数
宏定义：
    LIBSF_PATH  ：   待HOOK的so绝对路径
    HOOKED_FUNC ：   待HOOK的函数
**/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <jni.h>

#define LOG_TAG "INJECT"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

#define LIBSF_PATH  "/data/app/xh.helloworld-1/lib/arm/libnative-lib.so"
#define HOOKED_FUNC "Java_xh_helloworld_MainActivity_stringFromJNI"


jstring (*old_native_func)(JNIEnv *env, jobject clazz) = -1;

typedef struct tagHookInfo
{
    uint32_t m_nNewCode[3];     //新的汇编代码   jmp xxx
    uint16_t m_nOldCode[6];     //原先的汇编代码
    uint32_t m_nNewPfnAddr;     //新函数地址
    uint32_t m_nOldPfnAddr;     //原先的函数地址
} HOOK_INFO;

typedef unsigned int (*OLDFUC)(JNIEnv *, jobject);
OLDFUC g_pfnOldAddr = NULL;
HOOK_INFO g_HookInfo;
int FLAG = 0;

JNIEXPORT jstring new_native_func
  (JNIEnv *env, jobject clazz)
{
    LOGD("This is new_native_func");
    return (*env)->NewStringUTF(env, "Hello CFCA!");
}


//刷新指令缓存
void CacheFlush(unsigned int begin, unsigned int end)
{
    const int syscall = 0xf0002;

    __asm __volatile (
        "mov     r0, %0\n"
        "mov     r1, %1\n"
        "mov     r7, %2\n"
        "mov     r2, #0x0\n"
        "svc     0x00000000\n"
        :
        :   "r" (begin), "r" (end), "r" (syscall)
        :   "r0", "r1", "r7"
        );
}

//写入新指令
void WriteNewCode()
{
    memcpy((void *)g_HookInfo.m_nOldPfnAddr, g_HookInfo.m_nNewCode, sizeof(uint32_t) * 3);
    CacheFlush(g_HookInfo.m_nOldPfnAddr, g_HookInfo.m_nOldPfnAddr + sizeof(uint32_t) * 3);
}


//还原旧指令
void WriteOldCode()
{
    memcpy((void *)g_HookInfo.m_nOldPfnAddr, g_HookInfo.m_nOldCode, sizeof(uint16_t) * 6);
    CacheFlush(g_HookInfo.m_nOldPfnAddr, g_HookInfo.m_nOldPfnAddr + sizeof(uint16_t) * 6);
}


//新函数
jstring NewFuc(JNIEnv * jenv, jobject clazz)
{
    LOGD("Hello New Fuc");

    // 调用hook函数
    jstring ret = new_native_func(jenv, clazz);

    if(FLAG){
        //还原
        WriteOldCode();

        //调用原先的函数
        g_pfnOldAddr = (OLDFUC)((char *)(g_HookInfo.m_nOldPfnAddr) + 1);
        ret = (*g_pfnOldAddr)(jenv, clazz);

        //继续Hook
        WriteNewCode();
    }

    return ret;
}


void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        // self process
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );
                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp) ;
    }
    return (void *)addr;
}

int hook_native()
{
    int i = 0;
    void * base_addr = get_module_base(getpid(), LIBSF_PATH);
    LOGD("target so address = %p\n", base_addr);

    // 获得需要hook的函数地址
    void * handler = dlopen(LIBSF_PATH, RTLD_NOLOAD);
    if(!handler)
    {
        printf("%s", dlerror());
        return -1;
    }

    old_native_func = (uint32_t)dlsym(handler, HOOKED_FUNC) - 1;
    if(!old_native_func)
    {
        printf("%s", dlerror());
        return -1;
    }

    LOGD("orig fuc = %p\n", old_native_func);

    // 初始化hook结构体
    g_HookInfo.m_nNewPfnAddr = (uint32_t)NewFuc;
    g_HookInfo.m_nOldPfnAddr = (uint32_t)old_native_func;

    // BX PC; nop
    g_HookInfo.m_nNewCode[0] = 0x46C04778;

    // LDR PC [PC, #-0x4]
    g_HookInfo.m_nNewCode[1] = 0xE51FF004;

    // 新函数地址
    g_HookInfo.m_nNewCode[2] = g_HookInfo.m_nNewPfnAddr;

    // 保存原指令
    for (; i < 6; i++)
    {
        g_HookInfo.m_nOldCode[i] = ((uint16_t *)g_HookInfo.m_nOldPfnAddr)[i];
    }

    // 获得该函数所在的内存页面
    uint32_t page_size = getpagesize();
    uint32_t entry_page_start = (uint32_t)old_native_func & (~(page_size - 1));

    // 修改该内存属性为可读可写可执行
    if (mprotect((uint32_t *)entry_page_start, page_size, PROT_WRITE | PROT_READ | PROT_EXEC) != 0 )
    {
        LOGD("修改内存保护属性错误!");
        return -1;
    }

    // 写入新的汇编代码
    WriteNewCode();
}


/* 入口点 */
int hook_entry(char * a){
    LOGD("Hook success\n");
    LOGD("Start hooking\n");
    FLAG = atoi(a);
    hook_native();
    return 0;
}
