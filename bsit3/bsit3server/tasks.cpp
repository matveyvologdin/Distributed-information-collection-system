#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#pragma warning( once: 4996 )
#include <iostream>
#include <Windows.h>
#include "main.h"
#include <string>
#include <aclapi.h>
using namespace std;

//Функции сбора информации:
//os_version - Тип и версия ОС
//current_time - Текущее время
//uptime - Время, прошедшее с момента запуска ОС
//used_memory_info - Информация об используемой памяти
//type_connected_disks - Типы подключенных дисков
//free_space_on_disks - Свободное место на локальных дисках
//access_rights - Права доступа в текстовом виде к указанному файлу/папке/ключу реестра
//owner - - Владелец файла/папки/ключа реестра

void os_version(char* buf)
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFOW)&osvi);
	string data;
	data.append("OS version: ");
	if (osvi.dwMajorVersion == 4)
	{
		if (osvi.dwMinorVersion == 0)
			data.append("Windows 95");
		else if (osvi.dwMinorVersion == 10)
			data.append("Windows 98");
		else if (osvi.dwMinorVersion == 90)
			data.append("WindowsMe");
		else
			data.append("Unknown version");
	}
	else if (osvi.dwMajorVersion == 5)
	{
		if (osvi.dwMinorVersion == 0)
			data.append("Windows 2000");
		else if (osvi.dwMinorVersion == 1)
			data.append("Windows XP");
		else if (osvi.dwMinorVersion == 2)
			data.append("Windows 2003");
		else
			data.append("Unknown version");
	}
	else if (osvi.dwMajorVersion == 6)
	{
		if (osvi.dwMinorVersion == 0)
			data.append("Windows Vista");
		else if (osvi.dwMinorVersion == 1)
			data.append("Windows 7");
		else if (osvi.dwMinorVersion == 2)
			data.append("Windows 8");
		else if (osvi.dwMinorVersion == 3)
			data.append("Windows 8.1");
		else
			data.append("Unknown version");
	}
	else
		data.append("Unknown version");
	data.append("\n");
	strcpy(buf, data.c_str());
}

void cur_time(char* buf)
{
	SYSTEMTIME sm;
	GetLocalTime(&sm);
	string data;

	data.append("Current time: ");
	data.append(itoa((sm.wHour) / 10, new char[1], 10));
	data.append(itoa((sm.wHour) % 10, new char[1], 10));
	data.append(":");
	data.append(itoa(sm.wMinute / 10, new char[1], 10));
	data.append(itoa(sm.wMinute % 10, new char[1], 10));
	data.append(":");
	data.append(itoa(sm.wSecond / 10, new char[1], 10));
	data.append(itoa(sm.wSecond % 10, new char[1], 10));
	data.append(" ");
	data.append(itoa(sm.wDay / 10, new char[1], 10));
	data.append(itoa(sm.wDay % 10, new char[1], 10));
	data.append(".");
	data.append(itoa(sm.wMonth / 10, new char[1], 10));
	data.append(itoa(sm.wMonth % 10, new char[1], 10));
	data.append(".");
	data.append(itoa(sm.wYear, new char[1], 10));
	data.append("\n");
	strcpy(buf, data.c_str());
}

void uptime(char* buf)
{
	int hour, min, sec, msec = GetTickCount();
	hour = msec / (1000 * 60 * 60);
	min = msec / (1000 * 60) - hour * 60;
	sec = (msec / 1000) - (hour * 60 * 60) - min * 60;
	string data = "System uptime: ";
	data.append(itoa(hour / 10, new char[1], 10));
	data.append(itoa(hour % 10, new char[1], 10));
	data.append(":");
	data.append(itoa(min / 10, new char[1], 10));
	data.append(itoa(min % 10, new char[1], 10));
	data.append(":");
	data.append(itoa(sec / 10, new char[1], 10));
	data.append(itoa(sec % 10, new char[1], 10));
	data.append("\n");
	strcpy(buf, data.c_str());
}

void used_memory_info(char* buf)
{
	MEMORYSTATUS stat;
	GlobalMemoryStatus(&stat);
	string data;
	data.append("Memory load: ");
	data.append(itoa(stat.dwMemoryLoad, new char[1], 10));
	data.append("%\nAvailable/Total Phys memory: ");
	data.append(to_string((double)stat.dwAvailPhys / 1024.0 / 1024.0 / 1024.0));
	data.append("/");
	data.append(to_string((double)stat.dwTotalPhys / 1024.0 / 1024.0 / 1024.0));
	data.append("Gb\nAvailable/Total Program memory: ");
	data.append(to_string((double)stat.dwAvailPageFile / 1024.0 / 1024.0 / 1024.0));
	data.append("/");
	data.append(to_string((double)stat.dwTotalPageFile / 1024.0 / 1024.0 / 1024.0));
	data.append("Gb\nAvailable/Total Virtual memory: ");
	data.append(to_string((double)stat.dwAvailVirtual / 1024.0 / 1024.0 / 1024.0));
	data.append("/");
	data.append(to_string((double)stat.dwTotalVirtual / 1024.0 / 1024.0 / 1024.0));
	data.append("Gb\n");
	strcpy(buf, data.c_str());
}

void type_connected_disks(char* buf)
{
	int i, n, count = 0;
	char disks[26][4] = { 0 };
	DWORD dr = GetLogicalDrives();
	for (i = 0; i < 26; i++)
	{
		n = ((dr >> i) & 0x00000001);
		if (n == 1)
		{
			disks[count][0] = char(65 + i);
			disks[count][1] = ':';
			disks[count][2] = '\\';
			count++;
		}
	}
	string data = "";
	for (i = 0; i < count; i++)
	{
		data.append(disks[i]);
		int ret = GetDriveTypeA(disks[i]);
		switch (ret)
		{
		case DRIVE_UNKNOWN:
			data.append(" - unknown type, ");
			break;
		case DRIVE_REMOVABLE:
			data.append(" - floppy drive, ");
			break;
		case DRIVE_FIXED:
			data.append(" - hard disk drive, ");
			break;
		case DRIVE_REMOTE:
			data.append(" - remote (network) drive, ");
			break;
		case DRIVE_CDROM:
			data.append(" - CD-ROM drive, ");
			break;
		case DRIVE_RAMDISK:
			data.append(" - RAM disk, ");
			break;
		}
		char FSname[32];
		memset(FSname, 0, sizeof(FSname));

		GetVolumeInformationA(disks[i], NULL, NULL, NULL, NULL, NULL, FSname, 32);
		if (FSname[0] == 0)
			data.append("Unknown");
		else
			data.append(FSname);
		data.append(" filesystem\n");
	}
	strcpy(buf, data.c_str());
}

void free_space_on_disks(char* buf)
{
	int i, n, count = 0;
	char disks[26][3] = { 0 };
	DWORD dr = GetLogicalDrives();
	for (i = 0; i < 26; i++)
	{
		n = ((dr >> i) & 0x00000001);
		if (n == 1)
		{
			disks[count][0] = char(65 + i);
			disks[count][1] = ':';
			count++;
		}
	}
	string data = "";
	double freeSpace;
	int s = 0, b = 0, f = 0, c = 0;
	for (i = 0; i < count; i++)
	{

		if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
		{
			GetDiskFreeSpaceA(disks[i], (LPDWORD)&s, (LPDWORD)&b, (LPDWORD)&f, (LPDWORD)&c);
			freeSpace = (double)f * (double)s * (double)b / 1024.0 / 1024.0 / 1024.0;
			data.append(disks[i]);
			data.append("\\ ");
			data.append(to_string(freeSpace));
			data.append(" Gb\n");
		}
	}
	strcpy(buf, data.c_str());
}

void access_rights(char* buf, const char* path)
{
	path++;
	PACL pACL;
	ACL_SIZE_INFORMATION aclSizeInfo;
	PSECURITY_DESCRIPTOR pSD;
	string data = "";

	if (strncmp(path, "C:\\", 3) == 0 ||//Является файлом или
		strncmp(path, "C:/", 3) == 0 ||//директорией
		strncmp(path, "D:\\", 3) == 0 ||
		strncmp(path, "D:/", 3) == 0)
	{
		int ret = GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
			NULL, NULL, &pACL, NULL, &pSD);
		if (ret != ERROR_SUCCESS)
		{
			if (ret == 87)
				data.append("GetNamedSecurityInfoA error : Invalid path\n");
			else if (ret == 2)
				data.append("GetNamedSecurityInfoA error : Can't find file\n");
			else
				data.append("GetNamedSecurityInfoA Unknown error\n");
			strcpy(buf, data.c_str());
			return;
		}
	}
	else//является ключом реестра
	{
		int ret = GetNamedSecurityInfoA(path, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
			NULL, NULL, &pACL, NULL, &pSD);
		if (ret != ERROR_SUCCESS)
		{
			if (ret == 87)
				data.append("GetNamedSecurityInfoA error : Invalid path\n");
			else if (ret == 2)
				data.append("GetNamedSecurityInfoA error : Can't find file\n");
			else
				data.append("GetNamedSecurityInfoA Unknown error\n");
			strcpy(buf, data.c_str());
			return;
		}
	}
	int ret = GetAclInformation(pACL, &aclSizeInfo,
		sizeof(aclSizeInfo), AclSizeInformation);
	if (!ret)
	{
		strcpy(buf, "GetAclInformation error\n");
		return;
	}
	for (DWORD i = 0; i < aclSizeInfo.AceCount; i++)
	{
		LPVOID a;
		ret = GetAce(pACL, i, &a);
		if (!ret)
		{
			strcpy(buf, "GetAce error\n");
			return;
		}
		PSID pSID = (PSID) & (((ACCESS_ALLOWED_ACE*)a)->SidStart);
		char name[100], domain[100];
		DWORD nameLen = 100, domainLen = 100;
		SID_NAME_USE type;
		ret = LookupAccountSidA(NULL, pSID, name, &nameLen, domain, &domainLen, &type);
		if (!ret)
		{
			continue;
		}
		if (type == 1)
			data.append("For user ");
		else
			data.append("For group ");
		data.append(name);
		if (((ACCESS_ALLOWED_ACE*)a)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
			data.append(" Allowed ace type:  ");
		else if (((ACCESS_ALLOWED_ACE*)a)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
			data.append(" Denied ace type:  ");
		else if (((ACCESS_ALLOWED_ACE*)a)->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
			data.append(" System alarm ace type:  ");
		else if (((ACCESS_ALLOWED_ACE*)a)->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
			data.append(" System audit ace type:  ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & GENERIC_ALL) > 0)
			data.append("All, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & GENERIC_READ) > 0)
			data.append("Read, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & GENERIC_WRITE) > 0)
			data.append("Write, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & GENERIC_EXECUTE) > 0)
			data.append("Execute, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & DELETE) > 0)
			data.append("Delete, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & READ_CONTROL) > 0)
			data.append("Read control, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & WRITE_DAC) > 0)
			data.append("Write DAC, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & WRITE_OWNER) > 0)
			data.append("Write owner, ");
		if ((((ACCESS_ALLOWED_ACE*)a)->Mask & SYNCHRONIZE) > 0)
			data.append("Synchronize, ");
		data.erase(data.size() - 2);
		data.append("\n");
	}
	strcpy(buf, data.c_str());
}

void owner(char* buf, const char* path)
{
	path++;
	ACL_SIZE_INFORMATION aclSizeInfo;
	PSECURITY_DESCRIPTOR pSD;
	PSID pOwnerSid;
	string data = "";
	if (strncmp(path, "C:\\", 3) == 0 ||//Является файлом или
		strncmp(path, "C:/", 3) == 0 ||//директорией
		strncmp(path, "D:\\", 3) == 0 ||
		strncmp(path, "D:/", 3) == 0)
	{
		int ret = GetNamedSecurityInfoA(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
			&pOwnerSid, NULL, NULL, NULL, &pSD);
		if (ret != ERROR_SUCCESS)
		{
			if (ret == 87)
				data.append("GetNamedSecurityInfoA error : Invalid path\n");
			else if (ret == 2)
				data.append("GetNamedSecurityInfoA error : Can't find file\n");
			else
				data.append("GetNamedSecurityInfoA Unknown error\n");
			strcpy(buf, data.c_str());
			return;
		}
	}
	else//является ключом реестра
	{
		int ret = GetNamedSecurityInfoA(path, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
			&pOwnerSid, NULL, NULL, NULL, &pSD);
		if (ret != ERROR_SUCCESS)
		{
			if (ret == 87)
				data.append("GetNamedSecurityInfoA error : Invalid path\n");
			else if (ret == 2)
				data.append("GetNamedSecurityInfoA error : Can't find file\n");
			else
				data.append("GetNamedSecurityInfoA Unknown error\n");
			strcpy(buf, data.c_str());
			return;
		}
	}
	char name[100], domain[100];
	DWORD nameLen = 100, domainLen = 100;
	SID_NAME_USE type;
	LookupAccountSidA(NULL, pOwnerSid, name, &nameLen, domain, &domainLen, &type);

	data.append("Owner for ");
	data.append(path);
	data.append(" : ");
	data.append(name);
	data.append("\n");
	strcpy(buf, data.c_str());
}