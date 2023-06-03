#pragma once

#define OS_VERSION 1
#define CURRENT_TIME 2
#define UPTIME 3
#define USED_MEMORY_INFO 4
#define CONNECTED_DISKS_TYPES 5
#define FREE_SPACE_ON_DISKS 6
#define ACCESS_RIGHTS_ 7
#define OWNER 8
//task.cpp
void os_version(char* buf);
void cur_time(char* buf);
void uptime(char* buf);
void used_memory_info(char* buf);
void type_connected_disks(char* buf);
void free_space_on_disks(char* buf);
void access_rights(char* buf, const char* path);
void owner(char* buf, const char* path);
//crypto.cpp
void key_exchange(int key);