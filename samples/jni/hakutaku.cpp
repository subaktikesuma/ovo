#include "hakutaku.h"
#include <string>
#include <istream>
#include <iostream>
#include <sstream>
#include <cctype>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/mman.h>
#include <netdb.h>


struct req_access_process_vm {
    pid_t from;
    void __user* from_addr;
    pid_t to;
    void __user* to_addr;
    size_t size;
};

template <size_t N>
auto read_proc_file(pid_t pid, const char *name, char *dest) -> void {
    std::string file_path = "/proc/" + std::to_string(pid) + "/" + name;
    FILE* _fp = fopen(file_path.c_str(), "r");
    if (_fp != nullptr) {
        std::fgets(dest, N, _fp);
        std::fclose(_fp);
    } else {
        dest[0] = '\0';
    }
}

auto hak::get_process_list() -> std::vector<proc_stat> {
    std::vector<hak::proc_stat> list;
    auto *proc_dir = opendir("/proc");
    if (proc_dir == nullptr) {
        return {};
    }
    struct dirent* pid_file;
    char stat[256];
    while ((pid_file = readdir(proc_dir)) != nullptr) {
        if (pid_file->d_type != DT_DIR || ((std::isdigit(pid_file->d_name[0])) == 0)) {
            continue;
        }
        hak::proc_stat my_stat;
        pid_t pid = std::stoi(pid_file->d_name);
        read_proc_file<sizeof(stat)>(pid, "stat", stat);
        std::istringstream iss((std::string(stat)));
        iss >> my_stat.pid;
        iss >> my_stat.comm;
        iss >> my_stat.state;
        iss >> my_stat.ppid;
        if (my_stat.state == 'R' || my_stat.state == 'S' || my_stat.state == 'D') {
            list.push_back(my_stat);
        }
    }
    closedir(proc_dir);
    return std::move(list);
}

auto hak::get_pid_list() -> std::vector<pid_t> {
    std::vector<pid_t> list;
    auto *proc_dir = opendir("/proc");
    if (proc_dir == nullptr) {
        return {};
    }
    struct dirent* pid_file;
    char stat[256];
    while ((pid_file = readdir(proc_dir)) != nullptr) {
        if (pid_file->d_type != DT_DIR || ((std::isdigit(pid_file->d_name[0])) == 0)) {
            continue;
        }
        pid_t pid = std::stoi(pid_file->d_name);
        read_proc_file<sizeof(stat)>(pid, "stat", stat);
        std::istringstream iss((std::string(stat)));
        std::string token;
        for (int i = 0; i < 3; ++i) {
            iss >> token;
        }
        if (token == "R" || token == "S" || token == "D") {
            list.emplace_back(pid);
        }
    }
    closedir(proc_dir);
    return std::move(list);
}

auto hak::find_process(std::string_view package) -> pid_t {
    auto *proc_dir = opendir("/proc");
    if (proc_dir == nullptr) {
        return 0;
    }
    struct dirent* pid_file;
    char cmd_line[128];
    while ((pid_file = readdir(proc_dir)) != nullptr) {
        if (pid_file->d_type != DT_DIR || ((std::isdigit(pid_file->d_name[0])) == 0)) {
            continue;
        }
        pid_t pid = std::stoi(pid_file->d_name);
        read_proc_file<sizeof(cmd_line)>(pid, "cmdline", cmd_line);
        if (package == cmd_line) {
            pid_t p = std::stoi(pid_file->d_name);
            closedir(proc_dir);
            return p;
        }
    }
    closedir(proc_dir);
    return 0;
}

auto hak::get_module_base(pid_t pid, std::string_view module) -> uintptr_t {
    FILE *fp = nullptr;
    char *pch = nullptr;
    char filename[32];
    char line[512];
    uint64_t addr = 0;

    if (pid != -100)
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    else
        snprintf(filename, sizeof(filename), "/proc/self/maps");

    if ( (fp = fopen(filename, "r")) == nullptr ){
        printf("open %s failed!\n", filename);
        return 0;
    }

    while ( fgets(line, sizeof(line), fp) ){
        if ( strstr(line, module.data()) ){
            pch = strtok(line, "-");
            addr = strtoull(pch, nullptr, 16);
            break;
        }
    }

    fclose(fp);
    return addr;
}

auto hak::driver::find_driver_id() -> int {
    int sock;
    for (int i = AF_DECnet; i < AF_MAX; ++i) {
        sock = socket(i, SOCK_SEQPACKET, 0);
        if (sock < 0) {
            if (errno == ENOKEY) {
                sock = socket(i, SOCK_RAW, 0);
                if (sock > 0) {
                    break;
                }
            } else {
                continue;
            }
        }
    }

    if (sock < 0) {
        return -1;
    } else {
        close(sock);
    }
    return sock;
}

bool hak::driver::active() const {
    return sock > 0;
}

bool hak::driver::is_verbose() const {
    return verbose;
}

hak::driver::driver() {
    for (int i = AF_DECnet; i < AF_MAX; ++i) {
        sock = socket(i, SOCK_SEQPACKET, 0);
        if (sock < 0) {
            if (errno == ENOKEY) {
                sock = socket(i, SOCK_RAW, 0);
                if (sock > 0) {
                    return;
                }
            } else {
                continue;
            }
        }
    }
    verbose = true;
}

hak::driver::~driver() {
    if (active()) {
        close(sock);
    }
}

pid_t hak::driver::get_process_pid(std::string_view package) {
    pid_t pid = 0;
    void* data = new char[package.size() + 1];
    socklen_t len = package.size() + 1;
    std::copy(package.begin(), package.end(), static_cast<char*>(data));
    if(getsockopt(sock, len, (int) GET_PROCESS_PID, data, &len) < 0 && errno != 2033) {
        std::cout << "get pid by driver failed: " << strerror(errno) << std::endl;
        goto out;
    }
    pid = *(pid_t*) data;

    out:
    delete[] ((char*) data);
    return pid;
}
//pid_t hak::driver::get_process_pid(const std::string &package) const {
//    pid_t pid = 0;
//    void* data = new char[package.size() + 1];
//    socklen_t len = package.size() + 1;
//    std::copy(package.begin(), package.end(), static_cast<char*>(data));
//    if(getsockopt(sock, len, (int) GET_PROCESS_PID, data, &len) < 0) {
//        std::cout << "get pid by driver failed: " << strerror(errno) << std::endl;
//        goto out;
//    }
//    pid = *(pid_t*) data;
//
//    out:
//    delete[] ((char*) data);
//    return pid;
//}

bool hak::driver::is_process_alive_pid(pid_t pid) const {
    socklen_t alive = 0;
    if(getsockopt(sock, pid, (int) IS_PROCESS_ALIVE_PID, NULL, &alive) < 0 && errno != 2033) {
        std::cout << "is_process_alive_pid failed: " << strerror(errno) << std::endl;
        return false;
    }
    return alive == 1;
}

int hak::driver::attach_process_pid(pid_t pid) const {
    socklen_t len = 0;
    if(getsockopt(sock, pid, (int) ATTACH_PROCESS, nullptr, &len) < 0 && errno != 2033) {
        std::cout << "attach process failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return 0;
}

uintptr_t hak::driver::get_process_module_base(const std::string& module, int vm_flag) const {
    uintptr_t addr = 0;
    socklen_t len = module.size() + 1;
    if (len < 8) {
        len = 8;
    }
    char* data = new char[len];
    std::copy(module.begin(), module.end(), static_cast<char*>(data));
    if(getsockopt(sock, vm_flag, (int) GET_PROCESS_MODULE_BASE, data, &len) < 0 && errno != 2033) {
        std::cout << "get module base failed: " << strerror(errno) << std::endl;
        goto out;
    }
    addr = *(uintptr_t*) data;

    out:
    delete[] data;
    return addr;
}

// 读写10w次 70ms
size_t hak::driver::read_process_memory_ioremap(uintptr_t addr, void *buffer, size_t size) const {
    if(getsockopt(sock, size, (int) READ_PROCESS_MEMORY_IOREMAP, (void*) addr, (socklen_t*) buffer) < 0 && errno != 2033) {
        std::cout << "read process memory failed: " << strerror(errno) << std::endl;
        return 0;
    }
    return size;
}

size_t hak::driver::write_process_memory_ioremap(uintptr_t addr, void *buffer, size_t size) const {
    if(getsockopt(sock, size, (int) WRITE_PROCESS_MEMORY_IOREMAP, (void*) addr, (socklen_t*) buffer) < 0 && errno != 2033) {
        std::cout << "write process memory failed: " << strerror(errno) << std::endl;
        return 0;
    }
    return size;
}

// 读写10w次 220ms
int hak::driver::access_process_vm(pid_t from, uintptr_t from_addr, pid_t to, uintptr_t to_addr, size_t len) {
    req_access_process_vm req{};
    req.from = from;
    req.from_addr = (void*) from_addr;
    req.to = to;
    req.to_addr = (void*) to_addr;
    req.size = len;
    socklen_t data_len = sizeof(req);
    if(getsockopt(sock, len, (int) ACCESS_PROCESS_VM, &req, &data_len) < 0 && errno != 2033) {
        std::cout << "access process vm failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return len;
}

size_t hak::driver::read_process_memory(uintptr_t addr, void *buffer, size_t size) const {
    if(getsockopt(sock, size, (int) READ_PROCESS_MEMORY, (void*) addr, (socklen_t*) buffer) < 0 && errno != 2033) {
        std::cout << "read process memory failed: " << strerror(errno) << std::endl;
        return 0;
    }
    return size;
}

size_t hak::driver::write_process_memory(uintptr_t addr, void *buffer, size_t size) const {
    if(getsockopt(sock, size, (int) WRITE_PROCESS_MEMORY, (void*) addr, (socklen_t*) buffer) < 0 && errno != 2033) {
        std::cout << "write process memory failed: " << strerror(errno) << std::endl;
        return 0;
    }
    return size;
}

int hak::driver::remap_memory(uintptr_t addr, size_t size, void **buffer) const {
    if(getsockopt(sock, size, (int) REMAP_MEMORY, (void*) addr, (socklen_t*) addr) < 0 && errno != 2033) {
        std::cout << "remap memory failed: " << strerror(errno) << std::endl;
        return -1;
    }

    auto* buf = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, sock, 0);
    if (buf == MAP_FAILED) {
        std::cout << "mmap failed: " << strerror(errno) << std::endl;
        return -1;
    }

    *buffer = buf;
    return 0;
}


