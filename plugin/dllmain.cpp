// SelectAll —— EU4 和谈界面"一键全选对方省份"插件 v1.7
//
// 安装：把 selectall.dll 放入游戏目录 plugins/（由 version.dll 加载器自动加载）
// 使用：和谈界面打开时按 T —— 把当前页签（索取/给予）里所有"未选中且通过规则校验"
//       的条目逐个经游戏原生流程加入（CanAdd 校验 -> Add -> 刷新界面），
//       战争分数/外交点/AE/阶级领土变化与手动逐个点击完全一致。
//
// 实现要点（逆向结论，eu4.exe 1.37.5，1.37.0 地址见交接文档第 4 节）：
//   条目UI构造  0x1413124f0  ctor(entryUI, ctx, view, entryObj)   <- hook 捕获 view
//   条目UI析构  0x141306750  dtor(entryUI, flag)                  <- hook 置 view 失效
//   规则校验    0x14097a1c0  char canAdd(container, entry, out, 0, 0)
//   加入条款    0x14097a790  add(container, entry, 0, 0)
//   移除条款    0x14097a8d0  remove(container, entry, 0, 0)
//   刷新界面    0x141309120  refresh(view)
//   视图布局：mode 字节 view+0x660（0=索取 1=给予）
//             索取条目向量 view+0x290，容器 view+0x208
//             给予条目向量 view+0xd0， 容器 view+0x48
//             条目对象：选中标志 +0x20
// 以上地址全部经唯一特征码运行时定位。

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// ---------------- 日志（用 DebugView 查看） ----------------
static void Log(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA("[SelectAll] ");
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
}

// ---------------- 特征码扫描 ----------------
static uint8_t* g_text = nullptr;
static size_t g_text_size = 0;

static void InitTextRange() {
    HMODULE exe = GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)exe;
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)exe + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            g_text = (uint8_t*)exe + sec->VirtualAddress;
            g_text_size = sec->Misc.VirtualSize;
            return;
        }
    }
}

static void* FindPattern(const char* pattern) {
    uint8_t pat[128]; bool wild[128]; size_t n = 0;
    for (const char* p = pattern; *p && n < 128;) {
        if (*p == ' ') { ++p; continue; }
        if (*p == '?') { pat[n] = 0; wild[n] = true; ++n; p += (p[1] == '?') ? 2 : 1; continue; }
        pat[n] = (uint8_t)strtoul(p, (char**)&p, 16);
        wild[n] = false; ++n;
    }
    for (size_t i = 0; i + n <= g_text_size; ++i) {
        size_t j = 0;
        for (; j < n; ++j)
            if (!wild[j] && g_text[i + j] != pat[j]) break;
        if (j == n) return g_text + i;
    }
    return nullptr;
}

// ---------------- 目标函数（运行时解析） ----------------
namespace tgt {
    using canAdd_fn = char(__fastcall*)(void*, void*, void*, int, int);
    using add_fn    = void(__fastcall*)(void*, void*, int, int);
    using remove_fn = void(__fastcall*)(void*, void*, int, int);
    using refresh_fn= void(__fastcall*)(void*);
    canAdd_fn   canAdd = nullptr;
    add_fn      add = nullptr;
    remove_fn   remove = nullptr;
    refresh_fn  refresh = nullptr;
}

// ---------------- hook：近端桩 + 绝对跳转（不依赖 ±2GB 可达性） ----------------
struct Hook {
    uint8_t* target = nullptr;
    uint8_t* tramp = nullptr;   // 偷取的原函数头5字节 + 绝对jmp回 target+5
    void Install(void* handler);
};

static uint8_t* AllocNearExe() {  // 申请 eu4.exe ±2GB 内内存（E9 rel32 可达）
    uintptr_t base = (uintptr_t)GetModuleHandleW(nullptr);
    for (int i = 1; i < 128; ++i) {
        for (int sign = 1; sign >= -1; sign -= 2) {
            uintptr_t hint = base + sign * (uintptr_t)i * 0x4000000;
            if (hint < 0x10000) continue;
            uint8_t* p = (uint8_t*)VirtualAlloc((void*)hint, 64,
                                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

static void emit_abs_jmp(uint8_t* buf, int& n, void* addr) {  // movabs rax,addr; jmp rax
    buf[n++] = 0x48; buf[n++] = 0xB8;
    *(uint64_t*)(buf + n) = (uint64_t)addr; n += 8;
    buf[n++] = 0xFF; buf[n++] = 0xE0;
}

void Hook::Install(void* handler) {
    // 近端桩：E9(5B) 从 target 跳到桩；桩用绝对跳转进 handler（rax 为易失寄存器，入口处安全）
    uint8_t* stub = AllocNearExe();
    int n = 0;
    emit_abs_jmp(stub, n, handler);
    // 跳板：原5字节 + 绝对跳转回 target+5
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(tramp, target, 5);
    int m = 5;
    emit_abs_jmp(tramp, m, (void*)(target + 5));
    // 原函数头打 5 字节 E9 → 桩
    DWORD oldp;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldp);
    target[0] = 0xE9;
    *(int32_t*)(target + 1) = (int32_t)((uintptr_t)stub - (uintptr_t)target - 5);
    VirtualProtect(target, 5, oldp, &oldp);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    this->tramp = tramp;
}

// ---------------- 和谈视图捕获 ----------------
static void* g_view = nullptr;
static volatile bool g_view_alive = false;

static Hook g_hook_ctor, g_hook_dtor, g_hook_add, g_hook_remove;

using ctor_fn = void* (__fastcall*)(void*, void*, void*, void*);
static void* __fastcall my_ctor(void* entryUI, void* ctx, void* view, void* entryObj) {
    if (view) { g_view = view; g_view_alive = true; }
    auto orig = (ctor_fn)g_hook_ctor.tramp;
    return orig(entryUI, ctx, view, entryObj);
}

using dtor_fn = void(__fastcall*)(void*, unsigned);
static void __fastcall my_dtor(void* entryUI, unsigned flag) {
    g_view_alive = false;  // 条目销毁：可能是列表刷新（随后重建），也可能是界面关闭
    auto orig = (dtor_fn)g_hook_dtor.tramp;
    orig(entryUI, flag);
}

// ---------------- 一键全选 ----------------
static int g_sa_iter = 0;        // SEH 诊断：崩溃时的迭代位置
static bool g_sa_busy = false;   // 全选执行中（add 钩子跳过探测，防递归）
static volatile bool g_sa_pending = false;      // 快捷条约被点击：下一帧执行全选
static volatile bool g_uncheck_pending = false; // 省份被取消选中：下一帧反选快捷条约

// 快捷条款识别（发布名 sa_peace_select_all）：entry+0x30 = 条约定义指针（省份等普通条款为空），def+0x10 = 名字字符串
// （布局来自引擎 "PEACE_"+def->name 拼接处：buf@+0x10(SSO), len@+0x20, cap@+0x28）
static bool ProbeShortcutTreatyRaw(void* entry) {
    uint8_t* def = *(uint8_t**)((uint8_t*)entry + 0x30);
    if (!def) return false;
    uint8_t* strObj = def + 0x10;
    uint64_t cap = *(uint64_t*)(def + 0x28);
    const char* buf = cap > 15 ? *(const char**)strObj : (const char*)strObj;
    uint64_t len = *(uint64_t*)(def + 0x20);
    return len >= 19 && strncmp(buf, "sa_peace_select_all", 19) == 0;
}

static bool IsShortcutTreaty(void* entry) {  // SEH 防护：读到非法结构只吞不崩
    __try {
        return ProbeShortcutTreatyRaw(entry);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 条目类型（与引擎建列表同款虚调用 vt+0x78，返回描述符，首 DWORD = 类型）：
// 3=割让省份（省份页签）4/5=核心类 0xe/0x1c/0xf/0x13=其他条约 0x27=自定义条约（页签取自 def->category）
static int EntryType(void* entry) {
    __try {
        void* vt = *(void***)entry;
        if (!vt) return -1;
        auto getDesc = (void* (__fastcall*)(void*, void*))((void**)vt)[15];  // 0x78/8
        if (!getDesc) return -1;
        uint64_t dummy[8] = {};
        void* desc = getDesc(entry, dummy);
        if (!desc) return -1;
        return *(int*)desc;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

static void SelectAllWorker(uint8_t* view) {
    bool give = *(bool*)(view + 0x660) != 0;
    uintptr_t vecBase = (uintptr_t)view + (give ? 0xd0 : 0x290);
    void** beg = *(void***)vecBase;
    void** end = *(void***)(vecBase + 8);
    uint8_t* container = view + (give ? 0x48 : 0x208);

    // 先快照条目指针（Add 可能触发列表重建）
    void* entries[4096];
    int total = 0;
    for (void** p = beg; p && p < end && total < 4096; ++p)
        if (*p) entries[total++] = *p;

    int added = 0, skipped = 0, others = 0;
    g_sa_busy = true;
    for (int i = 0; i < total; ++i) {
        g_sa_iter = i;
        uint8_t* entry = (uint8_t*)entries[i];
        if (EntryType(entry) != 3) { ++others; continue; }            // 只全选割让省份条目
        if (*(bool*)(entry + 0x20)) { ++skipped; continue; }
        // canAdd 的第3参：游戏本体传栈上 {0,0,0} 的空向量结构（canAdd 会写入），不能传 nullptr
        uint64_t outVec[4] = {};
        if (!tgt::canAdd(container, entry, outVec, 0, 0)) { ++skipped; continue; }
        tgt::add(container, entry, 0, 0);
        ++added;
    }
    g_sa_busy = false;
    g_sa_iter = -1;
    tgt::refresh(view);
    Log("select-all: mode=%s total=%d provinces added=%d skipped=%d non-province=%d",
        give ? "give" : "demand", total, added, skipped, others);
}

static void DoSelectAll() {
    if (!g_view || !g_view_alive || !tgt::add || !tgt::canAdd || !tgt::refresh) {
        Log("ignored: view=%p alive=%d", g_view, (int)g_view_alive);
        return;
    }
    __try {
        SelectAllWorker((uint8_t*)g_view);
    }
    __except (Log("SEH: code=%08X iter=%d", GetExceptionCode(), g_sa_iter),
              EXCEPTION_EXECUTE_HANDLER) {
        Log("select-all aborted (exception swallowed)");
    }
}

// 拦截条款加入：快捷条约（my_annex_all*）正常加入（显示勾选），并触发下一帧全选省份
using add_fn_h = void(__fastcall*)(void*, void*, int, int);
static void __fastcall my_add(void* container, void* entry, int a, int b) {
    if (!g_sa_busy && IsShortcutTreaty(entry)) {
        g_sa_pending = true;
        Log("shortcut treaty clicked -> select-all pending");
    }
    auto orig = (add_fn_h)g_hook_add.tramp;
    orig(container, entry, a, b);
}

// 拦截条款移除：省份条目被取消选中 → 下一帧自动反选快捷条约
using remove_fn_h = void(__fastcall*)(void*, void*, int, int);
static void __fastcall my_remove(void* container, void* entry, int a, int b) {
    bool isProvince = !g_sa_busy && EntryType(entry) == 3;
    auto orig = (remove_fn_h)g_hook_remove.tramp;
    orig(container, entry, a, b);
    if (isProvince) g_uncheck_pending = true;
}

// 反选快捷条约：找到已勾选的 my_annex_all* 条目并移除
static void DoUncheck() {
    if (!g_view || !g_view_alive || !tgt::remove || !tgt::refresh) return;
    __try {
        uint8_t* view = (uint8_t*)g_view;
        bool give = *(bool*)(view + 0x660) != 0;
        uintptr_t vecBase = (uintptr_t)view + (give ? 0xd0 : 0x290);
        void** beg = *(void***)vecBase;
        void** end = *(void***)(vecBase + 8);
        uint8_t* container = view + (give ? 0x48 : 0x208);
        for (void** p = beg; p && p < end; ++p) {
            uint8_t* e = (uint8_t*)*p;
            if (!e || !*(bool*)(e + 0x20)) continue;
            if (!IsShortcutTreaty(e)) continue;
            g_sa_busy = true;
            tgt::remove(container, e, 0, 0);
            g_sa_busy = false;
            tgt::refresh(view);
            Log("shortcut treaty auto-unchecked (province deselected)");
            return;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_sa_busy = false;
        Log("uncheck: exception swallowed");
    }
}

// ---------------- 热键：IAT 钩 PeekMessageW（游戏主线程） ----------------
using PeekMessageW_t = BOOL(WINAPI*)(MSG*, HWND, UINT, UINT, UINT);
static PeekMessageW_t g_real_PeekMessageW = nullptr;
static bool g_key_was_down = false;

static BOOL WINAPI Hook_PeekMessageW(MSG* msg, HWND hwnd, UINT min, UINT max, UINT remove) {
    if (g_sa_pending) {              // 快捷条约点击 → 下一帧全选（避开点击调用栈重入）
        g_sa_pending = false;
        DoSelectAll();
    }
    if (g_uncheck_pending) {         // 省份被取消选中 → 下一帧反选快捷条约
        g_uncheck_pending = false;
        DoUncheck();
    }
    bool down = (GetAsyncKeyState('T') & 0x8000) != 0;
    if (down && !g_key_was_down) DoSelectAll();
    g_key_was_down = down;
    return g_real_PeekMessageW(msg, hwnd, min, max, remove);
}

static void HookIAT() {
    HMODULE exe = GetModuleHandleW(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)exe;
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)exe + dos->e_lfanew);
    auto imp = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)exe +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; imp->Name; ++imp) {
        auto dll = (const char*)((uint8_t*)exe + imp->Name);
        if (_stricmp(dll, "user32.dll") != 0) continue;
        if (!imp->OriginalFirstThunk) { Log("IAT: no INT, skip"); return; }
        // 名字查 OriginalFirstThunk（INT）；FirstThunk（IAT）只做补丁目标——
        // 加载器解析后 FirstThunk 里已是函数地址，不能当名字表读
        auto oft = (IMAGE_THUNK_DATA*)((uint8_t*)exe + imp->OriginalFirstThunk);
        auto ft = (IMAGE_THUNK_DATA*)((uint8_t*)exe + imp->FirstThunk);
        for (; ft->u1.Function; ++ft, ++oft) {
            if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) continue;
            auto byname = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)exe + oft->u1.AddressOfData);
            if (strcmp((const char*)byname->Name, "PeekMessageW") == 0) {
                DWORD oldp;
                VirtualProtect(&ft->u1.Function, 8, PAGE_READWRITE, &oldp);
                g_real_PeekMessageW = (PeekMessageW_t)ft->u1.Function;
                ft->u1.Function = (uintptr_t)Hook_PeekMessageW;
                VirtualProtect(&ft->u1.Function, 8, oldp, &oldp);
                Log("IAT hook ok: PeekMessageW");
                return;
            }
        }
    }
    Log("IAT hook FAILED (PeekMessageW not imported by eu4.exe)");
}

// ---------------- 入口 ----------------
static void InstallAll() {
    InitTextRange();
    uint8_t* ctor = (uint8_t*)FindPattern(
        "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 48 89 4C 24 08 55 48 8D 6C 24 A9"
        " 48 81 EC 90 00 00 00 49 8B D9 49 8B F0 48");
    // dtor 特征码：三组 lea vtable（位移随版本平移，必须通配）+ 尾部 mov edx,0xE0
    // （deleting dtor 的对象大小，1.37.0/1.37.5 皆为此值）作判别。
    // v1.6 教训：位移写死 A7 FD A6 00 → 函数平移即失配（1.37.5 上全军覆没的那一条）
    uint8_t* dtor = (uint8_t*)FindPattern(
        "48 89 5C 24 08 57 48 83 EC 20 48 8D 05 ? ? ? ? 8B DA 48 89 01 48 8B F9"
        " 48 8D 05 ? ? ? ? 48 89 41 38 48 8D 05 ? ? ? ? 48 89 41 68"
        " E8 ? ? ? ? F6 C3 01 74 ? BA E0 00 00 00 48 8B CF E8 ? ? ? ?"
        " 48 8B 5C 24 30 48 8B C7 48 83 C4 20 5F C3");
    uint8_t* canAdd = (uint8_t*)FindPattern(
        "48 89 5C 24 10 48 89 74 24 18 55 57 41 54 41 56 41 57 48 8B EC 48 81 EC 80 00"
        " 00 00 45 0F B6 F9");
    uint8_t* add = (uint8_t*)FindPattern(
        "48 89 6C 24 18 48 89 74 24 20 48 89 54 24 10 57 48 83 EC 30 41 0F B6 E9");
    uint8_t* refresh = (uint8_t*)FindPattern(
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 40 48 8B F1 B9 48 00 00 00 B8");
    uint8_t* removeF = (uint8_t*)FindPattern(
        "48 89 54 24 10 53 55 56 57 48 83 EC 48 41 0F B6 F1 48 8B EA C6 42 20 00");
    Log("ctor=%p dtor=%p canAdd=%p add=%p refresh=%p remove=%p",
        ctor, dtor, canAdd, add, refresh, removeF);
    if (!ctor || !dtor || !canAdd || !add || !refresh || !removeF) { Log("pattern resolve FAILED"); return; }
    tgt::canAdd = (tgt::canAdd_fn)canAdd;
    tgt::add = (tgt::add_fn)add;
    tgt::remove = (tgt::remove_fn)removeF;
    tgt::refresh = (tgt::refresh_fn)refresh;
    g_hook_ctor.target = ctor;
    g_hook_ctor.Install((void*)my_ctor);
    g_hook_dtor.target = dtor;
    g_hook_dtor.Install((void*)my_dtor);
    g_hook_add.target = add;
    g_hook_add.Install((void*)my_add);
    g_hook_remove.target = removeF;
    g_hook_remove.Install((void*)my_remove);
    Log("hooks installed (ctor/dtor/add/remove)");
}

static DWORD WINAPI InitThread(LPVOID) {
    Log("SelectAll v1.7 (release) loaded, pid=%lu", GetCurrentProcessId());
    InstallAll();
    HookIAT();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        // 全部内联完成（EU4dll 同款模式）：DllMain 里 CreateThread 有 loader lock 风险，
        // 且此处用到的 API（VirtualAlloc/VirtualProtect/OutputDebugString）均不需要 loader lock
        Log("SelectAll v1.7 (release) loaded, pid=%lu", GetCurrentProcessId());
        InstallAll();
        HookIAT();
    }
    return TRUE;
}
