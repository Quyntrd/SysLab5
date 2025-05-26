#include "check.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <utility>
#include <functional>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>

struct UserInfo {
    uid_t uid;
    std::string name;
    std::string home_dir;
    std::string shell;
    std::string shadow_hash;
    std::vector<std::pair<std::string, bool>> groups; // <group_name, is_admin>
};

// Read entire file by lines using FILE*
static void parse_colon_file(const std::string &path,
                             const std::function<void(const std::vector<std::string>&)> &handler) {
    int fd = check(open(path.c_str(), O_RDONLY));
    FILE *f = check(fdopen(fd, "r"));
    char *line = nullptr;
    size_t len = 0;
    ssize_t read_bytes;
    while ((read_bytes = getline(&line, &len, f)) != -1) {
        // strip newline
        if (read_bytes > 0 && (line[read_bytes-1]=='\n' || line[read_bytes-1]=='\r'))
            line[--read_bytes] = '\0';
        std::vector<std::string> parts;
        char *tok = std::strtok(line, ":");
        while (tok) {
            parts.emplace_back(tok);
            tok = std::strtok(nullptr, ":");
        }
        handler(parts);
    }
    free(line);
    fclose(f);
}

int main() {
    std::map<std::string, UserInfo> users;
    std::map<std::string, std::vector<std::string>> grp_members;
    std::map<std::string, std::vector<std::string>> grp_admins;
    std::map<gid_t, std::string> gid_to_group;

    // parse /etc/shadow to get hashes
    parse_colon_file("/etc/shadow", [&](const std::vector<std::string> &p){
        if (p.size() < 2) return;
        const std::string &user = p[0];
        const std::string &hash = p[1];
        users[user].name = user;
        users[user].shadow_hash = hash;
    });

    // parse /etc/gshadow to get admins
    parse_colon_file("/etc/gshadow", [&](const std::vector<std::string> &p){
        if (p.size() < 4) return;
        const std::string &grp = p[0];
        const std::string &admins_field = p[2];
        if(admins_field.empty()) return;
        size_t start = 0;
        while (start <= admins_field.size()) {
            size_t pos = admins_field.find(',', start);
            std::string name = admins_field.substr(start, pos - start);
            if (!name.empty()) grp_admins[grp].push_back(name);
            if (pos == std::string::npos) break;
            start = pos + 1;
        }
    });

    // Drop privileges
    check(setuid(getuid()));

    // parse /etc/passwd: uid, home, shell, primary gid
    std::map<std::string, gid_t> primary_gid;
    parse_colon_file("/etc/passwd", [&](const std::vector<std::string> &p){
        if (p.size() < 7) return;
        const std::string &user = p[0];
        uid_t uid = static_cast<uid_t>(std::stoul(p[2]));
        gid_t gid = static_cast<gid_t>(std::stoul(p[3]));
        const std::string &home = p[5];
        const std::string &shell = p[6];
        UserInfo &ui = users[user];
        ui.name = user;
        ui.uid = uid;
        ui.home_dir = home;
        ui.shell = shell;
        primary_gid[user] = gid;
    });

    // parse /etc/group: members and map gid group
    parse_colon_file("/etc/group", [&](const std::vector<std::string> &p){
        if (p.size() < 4) return;
        const std::string &grp = p[0];
        gid_t gid = static_cast<gid_t>(std::stoul(p[2]));
        gid_to_group[gid] = grp;
        std::string mems = p[3];
        size_t start = 0;
        while (start <= mems.size()) {
            size_t pos = mems.find(',', start);
            std::string name = mems.substr(start, pos - start);
            if (!name.empty()) grp_members[grp].push_back(name);
            if (pos == std::string::npos) break;
            start = pos + 1;
        }
    });

    // assemble groups per user
    for (auto &up : users) {
        const std::string &user = up.first;
        UserInfo &ui = up.second;
        // Primary group
        gid_t pgid = primary_gid[user];
        auto it = gid_to_group.find(pgid);
        if (it != gid_to_group.end()) {
            ui.groups.emplace_back(it->second, false);
        }
        // Supplementary groups
        for (const auto &gm : grp_members) {
            const std::string &gname = gm.first;
            for (const auto &member : gm.second) {
                if (member == user) {
                    bool is_admin = false;
                    auto ait = grp_admins.find(gname);
                    if (ait != grp_admins.end()) {
                        for (const auto &adm : ait->second) {
                            if (adm == user) { is_admin = true; break; }
                        }
                    }
                    ui.groups.emplace_back(gname, is_admin);
                    break;
                }
            }
        }
    }

    // output
    for (const auto &up : users) {
        const UserInfo &ui = up.second;
        std::cout << "UID: " << ui.uid << ",\nUser: " << ui.name << std::endl;
        std::cout << "  Home: " << ui.home_dir << ",\n  Shell: " << ui.shell << std::endl;
        std::cout << "  Shadow hash: " << ui.shadow_hash << std::endl;
        std::cout << "  Groups:" << std::endl;
        for (const auto &g : ui.groups) {
            std::cout << "    - " << g.first;
            if (g.second) std::cout << " [AAAAAAAAAAAAADDDDMMMMIIINNN]";
            std::cout << std::endl;
        }
        std::cout << "-----------------------" << std::endl;
    }

    return EXIT_SUCCESS;
}
