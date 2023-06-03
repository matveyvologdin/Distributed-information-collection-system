#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <wincrypt.h>
#include "main.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_CLIENTS (100)

using namespace std;

void init();
void help();
void usage();
void writeLog(char* buf, int size);

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Rus");
	
	init();

	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	if (s == INVALID_SOCKET)
	{
		printf("WSASocket error\n");
		return 0;
	}

	char* input_buf = new char[32];
	char* send_buf = new char[128];
	char recv_buf[512];
	memset(input_buf, 0, sizeof(input_buf));
	memset(send_buf, 0, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));

	if (argc < 3 || argc > 5 ||
		argc == 5 && atoi(argv[3]) != 7 && atoi(argv[3]) != 8 ||
		argc == 4 && (atoi(argv[3]) == 7 || atoi(argv[3]) == 8))
	{
		usage();
		help();
		return 0;
	}
	else if (argc == 3)
		help();
	else if (argc >= 4)
		strcpy(input_buf, argv[3]);
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(atoi(argv[2]));


	if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		closesocket(s);
		printf("Error: connect()\n");
		return 0;
	}

	printf("Соединение установлено\n");

	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTKEY sessionKey;
	HCRYPTKEY publicKey;
	HCRYPTKEY privateKey = NULL;
	DWORD dwPublicKeyLen = 1024;//длина открытого ключа
	DWORD dwPrivateKeyLen = 1024;//длина закрытого ключа
	DWORD dwSessionKeyLen = 1024;
	BYTE pbPublicKey[1024];//открытый ключ
	BYTE pbPrivateKey[1024];//закрытый ключ
	BYTE pbSessionKey[1024];
	ZeroMemory(pbPublicKey, sizeof(pbPublicKey));
	ZeroMemory(pbPrivateKey, sizeof(pbPrivateKey));
	ZeroMemory(pbSessionKey, sizeof(pbSessionKey));

	//инициализируем контекст шифрования
	if (!CryptAcquireContext(&hProv, NULL, MS_STRONG_PROV, PROV_RSA_FULL, NULL))
		printf("CryptAcquireContext error %d\n", GetLastError());

	//генерируем пару ключей
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, 1024 << 16 | CRYPT_EXPORTABLE, &hKey))
		printf("CryptGenKey error %d\n", GetLastError());

	//достаём публичный ключ
	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen))
		printf("CryptExportKey error %d\n", GetLastError());

	//достаём приватный ключ
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbPrivateKey, &dwPrivateKeyLen))
		printf("CryptExportKey error %d\n", GetLastError());

	//получаем дескриптор приватного ключа
	if (!CryptImportKey(hProv, pbPrivateKey, dwPrivateKeyLen, NULL, NULL, &privateKey))
		printf("CryptImportKey error %d\n", GetLastError());

	char* sendBuf = new char[512];
	int ret;
	
	//отправляем публичный ключ
	sendBuf = (char*)&pbPublicKey;
	sendBuf[dwPublicKeyLen] = '\n';

	ret = send(s, sendBuf, dwPublicKeyLen + 1, 0);
	if (ret < 0)
	{
		printf("send error %d\n", WSAGetLastError());
		return 0;
	}

	//получаем зашифрованный сеансовый ключ
	dwSessionKeyLen = recv(s, (char*)&pbSessionKey, 512, 0);
	if (ret < 0)
	{
		printf("recv error %d\n", WSAGetLastError());
		return 0;
	}

	//расшифровываем сессионный ключ
	if (!CryptImportKey(hProv, pbSessionKey, dwSessionKeyLen, privateKey, NULL, &sessionKey))
		printf("CryptImportKey error %d\n", GetLastError());

	if (argc == 3)
		cin >> input_buf;
	if (strcmp(input_buf, "1") == 0 || strcmp(input_buf, "os_version") == 0)
		strcpy(send_buf, "1");
	else if (strcmp(input_buf, "2") == 0 || strcmp(input_buf, "cur_time") == 0)
		strcpy(send_buf, "2");
	else if (strcmp(input_buf, "3") == 0 || strcmp(input_buf, "uptime") == 0)
		strcpy(send_buf, "3");
	else if (strcmp(input_buf, "4") == 0 || strcmp(input_buf, "used_memory_info") == 0)
		strcpy(send_buf, "4");
	else if (strcmp(input_buf, "5") == 0 || strcmp(input_buf, "type_connected_disks") == 0)
		strcpy(send_buf, "5");
	else if (strcmp(input_buf, "6") == 0 || strcmp(input_buf, "free_space_on_disks") == 0)
		strcpy(send_buf, "6");
	else if (strcmp(input_buf, "7") == 0 || strcmp(input_buf, "access_rights") == 0)
	{
		strcpy(send_buf, "7");
		strcat(send_buf, argv[4]);
	}
	else if (strcmp(input_buf, "8") == 0 || strcmp(input_buf, "owner") == 0)
	{
		strcpy(send_buf, "8");
		strcat(send_buf, argv[4]);

	}
	else
	{
		help();
		return 0;
	}
	int sendBufSize = strlen(send_buf);
	//шифруем отправляемый буфер сессионным ключом
	if (!CryptEncrypt(sessionKey, NULL, TRUE, NULL,
		(BYTE*)send_buf, (DWORD*)&sendBufSize, sendBufSize))
		printf("CryptEncrypt error %d\n", GetLastError());

	send_buf[sendBufSize] = '\n';

	int bytes_send, recvBufSize = 0;
	//отправляем сообщение
	bytes_send = send(s, send_buf, sendBufSize + 1, 0);
	//получаем ответ
	recvBufSize = recv(s, recv_buf, 512, 0);
	//расшифровываем ответ сессионным ключом
	if (!CryptDecrypt(sessionKey, NULL, TRUE, NULL,
		(BYTE*)recv_buf, (DWORD*)&recvBufSize))
		printf("CryptDecrypt error %d\n", GetLastError());

	writeLog(recv_buf, strlen(recv_buf));

	printf("Информация записана в файл log.txt");

	//delete[] recv_buf;
	delete[] send_buf;
	delete[] input_buf;

	return 0;
}

void init()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
		exit(-1);
	}
}

void usage()
{
	printf("Формат ввода:\n"
		"ip port [command] [path]\n");
}

void help()
{
	printf("Возможно выполнить следующие виды команд:\n"
		"1.os_version - Тип и версия ОС\n"
		"2.current_time - Текущее время\n"
		"3.uptime - Время, прошедшее с момента запуска ОС\n"
		"4.used_memory_info - Информация об используемой памяти\n"
		"5.type_connected_disks - Типы подключенных дисков\n"
		"6.free_space_on_disks - Свободное место на локальных дисках\n"
		"7.access_rights [path] - Права доступа в текстовом виде к указанному файлу/папке/ключу реестра\n"
		"8.owner [path] - Владелец указанного файла/папки/ключа реестра\n");
}

void writeLog(char *buf, int size)
{
	ofstream file;
	file.open(LOG_FILE, ios::app);
	file.write(buf, size);
	file.close();
}