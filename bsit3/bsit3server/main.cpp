#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#include <iostream>
#include "main.h"
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_CLIENTS (100)

using namespace std;

struct client_ctx
{
	int socket;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[512]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
	 // Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY publicKey = NULL;
	HCRYPTKEY sessionKey = NULL;
};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;
// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	int ret = WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
	if (ret < 0)
		printf("WSARecv error: %d\n", WSAGetLastError());
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf; buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	int ret = WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
	if (ret < 0)
		printf("WSASend error: %d\n", WSAGetLastError());
}
// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, * remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr**)&local_addr, &local_addr_sz, (struct sockaddr**)&remote_addr,
				&remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}
// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. 
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16,
		sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int* len)
{
	if (g_ctxs[idx].buf_recv[g_ctxs[idx].sz_recv - 1] == '\n')
		return 1;
	return 0;
}

int strlen_my(char* buf)
{
	int i = 511;
	while (buf[i] == '\0' && i > 0)
		i--;

	return i;
}

void strncpy_my(char* dst, char* src, int count)
{
	while (count)
	{
		count--;
		dst[count] = src[count];
	}
}

void io_serv()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
		return;
	}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	//Проверка созданного сокета
	if (s == INVALID_SOCKET)
	{
		printf("WSASocket error\n");
		return;
	}

	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n"); 
		return;
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));

	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	g_ctxs[0].socket = s;
	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
			// Иначе поступило событие по завершению операции от клиента. 
			// Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key,
							&g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						// Если строка полностью пришла, то сформировать ответ и начать его\
							отправлять
						if (g_ctxs[key].sessionKey != NULL)//пришла команда
						{
							g_ctxs[key].sz_recv--;
							if (!CryptDecrypt(g_ctxs[key].sessionKey, NULL, TRUE, NULL,
								(BYTE*)g_ctxs[key].buf_recv, (DWORD*)&g_ctxs[key].sz_recv))
								printf("CryptDecrypt error %d\n", GetLastError());

							int way = g_ctxs[key].buf_recv[0] - '0';

							switch (way)
							{
							case OS_VERSION:
								os_version(g_ctxs[key].buf_send);
								break;
							case CURRENT_TIME:
								cur_time(g_ctxs[key].buf_send);
								break;
							case UPTIME:
								uptime(g_ctxs[key].buf_send);
								break;
							case USED_MEMORY_INFO:
								used_memory_info(g_ctxs[key].buf_send);
								break;
							case CONNECTED_DISKS_TYPES:
								type_connected_disks(g_ctxs[key].buf_send);
								break;
							case FREE_SPACE_ON_DISKS:
								free_space_on_disks(g_ctxs[key].buf_send);
								break;
							case ACCESS_RIGHTS_:
								g_ctxs[key].buf_recv[g_ctxs[key].sz_recv] = '\0';
								access_rights(g_ctxs[key].buf_send, g_ctxs[key].buf_recv);
								break;
							case OWNER:
								g_ctxs[key].buf_recv[g_ctxs[key].sz_recv] = '\0';
								owner(g_ctxs[key].buf_send, g_ctxs[key].buf_recv);
								break;
							default:
							{
								strcpy(g_ctxs[key].buf_send, "command");
							}
							}
							g_ctxs[key].sz_send_total = strlen_my(g_ctxs[key].buf_send) + 1;
							//шифруем выходное сообщение сессионным ключом
							if (!CryptEncrypt(g_ctxs[key].sessionKey, NULL, TRUE, NULL,
								(BYTE*)g_ctxs[key].buf_send,
								(DWORD*)&g_ctxs[key].sz_send_total,
								g_ctxs[key].sz_send_total))
								printf("CryptEncrypt error %d\n", GetLastError());
						}
						else//пришел открытый ключ
						{
							key_exchange(key);
						}
						
						g_ctxs[key].sz_send = 0;
						memset(g_ctxs[key].buf_recv, 0, sizeof(g_ctxs[key].buf_recv));
						schedule_write(key);
					}
					else
					{
						// Иначе - ждем данные дальше
						schedule_read(key);
					}
					}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, 512);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
		}
	}
}

void key_exchange(int key)
{
	
	HCRYPTKEY hKey;
	HCRYPTKEY EncryptedSessionKey = NULL;
	DWORD dwPublicKeyLen = 1024;//длина открытого ключа
	DWORD dwPrivateKeyLen = 1024;//длина закрытого ключа
	DWORD dwSessionKeyLen = 1024;
	DWORD dwEncryptedSessionKeyLen = 1024;
	BYTE pbPublicKey[1024];//открытый ключ
	BYTE pbPrivateKey[1024];//закрытый ключ
	BYTE pbSessionKey[1024];
	BYTE pbEncryptedSessionKey[1024];
	ZeroMemory(pbPublicKey, sizeof(pbPublicKey));
	ZeroMemory(pbPrivateKey, sizeof(pbPrivateKey));
	ZeroMemory(pbSessionKey, sizeof(pbSessionKey));

	//инициализируем контекст шифрования
	if (!CryptAcquireContext(&g_ctxs[key].hProv, NULL, MS_STRONG_PROV, PROV_RSA_FULL, NULL))
		printf("CryptAcquireContext error %d\n", GetLastError());
	//генерируем сессионный ключ
	if (!CryptGenKey(g_ctxs[key].hProv, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &g_ctxs[key].sessionKey))
		printf("CryptGenKey error %d\n", GetLastError());
	//получаем дескриптор публичного ключа
	if (!CryptImportKey(g_ctxs[key].hProv, (BYTE*)g_ctxs[key].buf_recv, g_ctxs[key].sz_recv - 1, NULL, NULL, &g_ctxs[key].publicKey))
		printf("CryptImportKey error %d\n", GetLastError());

	//шифруем сессионный ключ с помощью публичного
	if (!CryptExportKey(g_ctxs[key].sessionKey, g_ctxs[key].publicKey, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[key].buf_send, &dwSessionKeyLen))
		printf("CryptExportKey error %d\n", GetLastError());
	
	g_ctxs[key].sz_send_total = dwSessionKeyLen;
}

int main()
{
	setlocale(LC_ALL, "Rus");
	io_serv();
	return 0;
}