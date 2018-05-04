// Note that I am using:
// https://github.com/francoiscolas/multipart-parser
// Assuming it is compiled in subdirectory multipart-parser, I compile with:
// gcc server_example.c multipart-parser/multipartparser.o

// Standard C libraries
#include <stdio.h>
#include <stdlib.h>

// Various POSIX libraries
#include <unistd.h>

// Various string utilities
#include <string.h>

// Operations on files
#include <fcntl.h>

// Gives us access to the C99 "bool" type
#include <stdbool.h>

// Includes for socket programming
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

// Memory management stuff
#include <sys/mman.h>

// Multipart parser
#include "multipart-parser/multipartparser.h"

#define perror(err) fprintf(stderr, "%s\n", err);

#define BUFLEN 1024
#define FAIL -1
#define SUCCESS 0

//
// Global variables
//
int server_fd = -1;
char *root;         // Root directory from which the server serves files
char buffer[1024];
char secret_key[100];
int total_read = 0;
int new_fd = 0;

int LOG_ENABLED = 1;

void logmsg(char *message) {
  printf("%s\n", message);
  fflush(stdout);
}

/*
 * Returns true if string `pre` is a prefix of `str`
 */
bool prefix(const char *pre, const char *str)
{
  return strncmp(pre, str, strlen(pre)) == 0;
}

void hello_world() {
  printf("Hello, world!\n");
  fflush(stdout);
}

/*
 * cerror - returns an error message to the client
 */
void cerror(FILE *stream, char *cause, char *errnum,
	    char *shortmsg, char *longmsg) {
  fprintf(stream, "HTTP/1.1 %s %s\n", errnum, shortmsg);
  fprintf(stream, "Content-type: text/html\n");
  fprintf(stream, "\n");
  fprintf(stream, "<html><title>Tiny Error</title>");
  fprintf(stream, "<body bgcolor=""ffffff"">\n");
  fprintf(stream, "%s: %s\n", errnum, shortmsg);
  fprintf(stream, "<p>%s: %s\n", longmsg, cause);
  fprintf(stream, "<hr><em>The Tiny Web server</em>\n");
}

struct fatFilePointer {
  int length;
  char *data;
};

#define CHUNK_SIZE 100000

struct fatFilePointer read_file(char *name)
{
  FILE *file;
  char *buffer;
  unsigned long fileLen;
  struct fatFilePointer ret;
  ret.length = 0;
  ret.data = NULL;

  //Open file
  file = fopen(name, "rb");
  if (!file)
    {
      fprintf(stderr, "Unable to open file %s", name);
      return ret;
    }

  fileLen = 0;
  buffer = malloc(CHUNK_SIZE);
  char temp[CHUNK_SIZE];
  unsigned long bytesRead;

  do {
    bytesRead = fread(temp,1,CHUNK_SIZE,file);
    char *newbuffer = malloc(fileLen + CHUNK_SIZE);
    for (unsigned long i = 0; i < fileLen; i++) {
      newbuffer[i] = buffer[i];
    }
    for (unsigned long i = 0; i < bytesRead; i++) {
      newbuffer[fileLen + i] = temp[i];
    }
    fileLen += bytesRead;
    char *oldbuf = buffer;
    buffer = newbuffer;
    free(oldbuf);
  } while (bytesRead == CHUNK_SIZE);

  ret.length = fileLen;
  ret.data = buffer;
  char dir[1024];
  getcwd(dir, 2014);
  return ret;
}

int starts_with(const char *a, const char *b)
{
  if (strncmp(a, b, strlen(b)) == 0) return 1;
  return 0;
}

int on_data(multipartparser *parser,const char *at, size_t length) {
  write(new_fd,at,length);
  total_read += length;
  return 0;
}



int is_dir(const char* filepath){
  struct stat st;
  if (stat(filepath, &st) != 0){
    return 0;
  }
  return S_ISDIR(st.st_mode);
}

int is_file(const char* filepath){
  struct stat st;
  if (stat(filepath, &st) != 0){
    return 0;
  }
  return S_ISREG(st.st_mode);
}


int recur_mkdir(char* filepath) {
  char* pre_dir = filepath + 2;
  char* next_dir;
  while((next_dir= strchr(pre_dir, '/')) != NULL) {
    int size = strlen(pre_dir) - strlen(next_dir) + 1;
    char* cur_dir = malloc(sizeof(char) * (size+1));
    bzero(cur_dir, size);
    cur_dir[size-1] = '\0';
    strncpy(cur_dir, pre_dir, strlen(pre_dir) - strlen(next_dir));
    if(access(cur_dir, R_OK | W_OK) != 0) {
      if(errno == ENOENT) {
	if(mkdir(cur_dir, S_IRWXU | S_IRWXG | S_IROTH) == 0){
	  chdir(cur_dir);
	} else {
	  return -1;
	}
      } else if (errno == EACCES){
	return -1;
      }
    } else {
      chdir(cur_dir);
    }
    pre_dir = next_dir + 1;
    free(cur_dir);
    //    next_dir = next_dir + 1;
  }
  char* token = strstr(root, "/");
  chdir(token+1);
  return 0;
}

void server_result(FILE* stream, char* filename, int contents_length){
  char filetype[30];

  /* serve static content */
  if (strstr(filename, ".html") != NULL ) {
    strncpy(filetype, "text/html", strlen("text/html"));
  } else if (strstr(filename, ".gif") != NULL) {
    strncpy(filetype, "image/gif", strlen("image/gif"));
  } else if (strstr(filename, ".jpg") != NULL) {
    strncpy(filetype, "image/jpg", strlen("image/jpg"));
  } else {
    strncpy(filetype, "text/plain", strlen("text/plain"));
  }

  /* print response header */
  fprintf(stream, "HTTP/1.1 200 OK\n");
  fprintf(stream, "Server: Tiny Web Server\n");
  fprintf(stream, "Content-length: %d\n", contents_length);
  fprintf(stream, "Content-type: %s\n", filetype);
  fprintf(stream, "\r\n");
  fflush(stream);
}

/*
 * Responsd to an HTTP request
 */
void serve_http(int socket) {
  char method[100];
  char filename[100];
  char filetype[30];
  char version[100];
  char cgiargs[100];
  char uri[200];
  char *p;
  FILE *stream = fdopen(socket, "r+");
  char *partial_body = malloc(BUFLEN);
  int used = 0;
  struct stat sbuf;
  int fd = -1;
  fgets(buffer, BUFLEN, stream);
  sscanf(buffer, "%s %s %s", method, uri, version);
  strncpy(partial_body,buffer, BUFLEN);
  used += strlen(buffer);
  int length = 0;
  char boundary[50];
  
  // Parse each header in sequence
  while(strcmp(buffer, "\r\n")) {
    fgets(buffer, BUFLEN, stream);
    strncat(partial_body,buffer, strlen(buffer));
    used += strlen(buffer);
    if (starts_with(buffer,"Content-Length:")) {
      sscanf(buffer,"Content-Length: %d",&length);
    }
    if (starts_with(buffer,"Content-Type: multipart/form-data;")) {
      sscanf(buffer,"Content-Type: multipart/form-data; boundary=%s",boundary);
    }
  }

  strncat(partial_body,buffer, strlen(buffer));
  used += strlen(buffer);

  char *body = malloc(length);
  int read = fread(body,1,length,stream);
  char *total = malloc(strlen(partial_body)+length);
  memcpy(total,partial_body,strlen(partial_body));
  memcpy(total+strlen(partial_body),body,length);

  strncpy(cgiargs, "", strlen(""));
  strncpy(filename, ".", strlen("."));
  strncat(filename, uri, strlen(uri));

  if(strstr(filename, "..") != NULL) {
    new_fd = -1;
    cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
    bzero(method, 100);
    bzero(filename, 100);
    bzero(filetype, 30);
    bzero(version, 100);
    bzero(cgiargs, 100);
    bzero(uri, 200);
    fclose(stream);
    close(socket);
    free(body);
    free(total);
    return;
  }
  
  if (strcasecmp(method, "DELETE") == 0) {
    if (uri[strlen(uri)-1] == '/') {
      strcat(filename, "index.html");
    }
    if(access(filename, R_OK | W_OK) == 0) {
      server_result(stream, filename, 0);
      remove(filename);
      bzero(method, 100);
      bzero(filename, 100);
      bzero(filetype, 30);
      bzero(version, 100);
      bzero(cgiargs, 100);
      bzero(uri, 200);
      return;
    } else {
      if (errno == EACCES) {
	new_fd = -1;
	cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
	bzero(method, 100);
	bzero(filename, 100);
	bzero(filetype, 30);
	bzero(version, 100);
	bzero(cgiargs, 100);
	bzero(uri, 200);
	fclose(stream);
	close(socket);
	return;
      } else if (errno == ENOENT) {
	new_fd = -1;
	cerror(stream, method, "400", "Invalid Request", "File does not exist");
	bzero(method, 100);
	bzero(filename, 100);
	bzero(filetype, 30);
	bzero(version, 100);
	bzero(cgiargs, 100);
	bzero(uri, 200);
	fclose(stream);
	close(socket);
      }
    }
  } else if (strcasecmp(method, "PUT") == 0) {
    /* read (and ignore) the HTTP headers */
    /* parse the uri [crufty] */
    if (uri[strlen(uri)-1] == '/') {
      strcat(filename, "index.html");
    }
    char workingdir[1024];
    getcwd(workingdir, 1024);
    struct stat st;
    int result = stat(filename, &st);
    if (result == FAIL) {
      new_fd = -1;
      cerror(stream, method, "400", "Invalid Request", "File does not exist");
      bzero(method, 100);
      bzero(filename, 100);
      bzero(filetype, 30);
      bzero(version, 100);
      bzero(cgiargs, 100);
      bzero(uri, 200);
      fclose(stream);
      close(socket);
      return;
    }
    if(access(filename, R_OK | W_OK) == 0) {
      // file readable and writable
      if((new_fd = open(filename,O_WRONLY | O_TRUNC)) == -1) {
	printf("open file failed : %d\n", errno);
      }
    } else {
      new_fd = -1;
      cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
      bzero(method, 100);
      bzero(filename, 100);
      bzero(filetype, 30);
      bzero(version, 100);
      bzero(cgiargs, 100);
      bzero(uri, 200);
      fclose(stream);
      close(socket);
      return;
    }

    multipartparser_callbacks callbacks;
    multipartparser parser;
    multipartparser_callbacks_init(&callbacks); // It only sets all callbacks to NULL.
    callbacks.on_data = &on_data;
    multipartparser_init(&parser, boundary);
    int nparsed = multipartparser_execute(&parser, &callbacks, total, strlen(partial_body)+length);
    close(new_fd);
    server_result(stream, filename, total_read);
    bzero(method, 100);
    bzero(filename, 100);
    bzero(filetype, 30);
    bzero(version, 100);
    bzero(cgiargs, 100);
    bzero(uri, 200);
    new_fd = -1;
    fflush(stream);
    return;
  } else if (strcasecmp(method, "POST") == 0) {
    /* read (and ignore) the HTTP headers */
    if (uri[strlen(uri)-1] == '/') {
      strcat(filename, "index.html");
    }
    char workingdir[1024];
    getcwd(workingdir, 1024);
    struct stat st;
    int result = stat(filename, &st);
    if(result == FAIL) {
      if(errno == ENOENT) {
        //path does not exists
        // recursively make directory or simply return false
        int makedir = recur_mkdir(filename);
        char changedir[1024];
        strncpy(changedir, workingdir, strlen(workingdir));
        char* cur_root = strstr(root, "/");
        strncat(changedir, cur_root, strlen(cur_root));
        changedir[strlen(workingdir) + strlen(root) + 1] = '\0';
        chdir(changedir);
        char cur[1024];
        getcwd(cur, 1024);
        if (makedir == -1) {
          new_fd = -1;
          cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
          bzero(method, 100);
          bzero(filename, 100);
          bzero(filetype, 30);
          bzero(version, 100);
          bzero(cgiargs, 100);
          bzero(uri, 200);
          fclose(stream);
          close(socket);
          return;
        } else {
          if((new_fd = open(filename, O_CREAT | O_WRONLY, 0774)) == -1) {
            printf("create file failed %d\n", errno);
	    cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
	    bzero(method, 100);
	    bzero(filename, 100);
	    bzero(filetype, 30);
	    bzero(version, 100);
	    bzero(cgiargs, 100);
	    bzero(uri, 200);
	    fclose(stream);
	    close(socket);
          }
        }
      }
    } else if (result == SUCCESS) {
      if(access(filename, R_OK | W_OK) == 0) {
        // file readable and writable
        if((new_fd = open(filename,O_WRONLY)) == -1) {
          printf("open file failed 6 : %d\n", errno);
	  cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
	  bzero(method, 100);
	  bzero(filename, 100);
	  bzero(filetype, 30);
	  bzero(version, 100);
	  bzero(cgiargs, 100);
	  bzero(uri, 200);
	  fclose(stream);
	  close(socket);
        }
      } else {
        new_fd = -1;
        cerror(stream, method, "403", "Forbidden", "File is forbidden for access");
        bzero(method, 100);
        bzero(filename, 100);
        bzero(filetype, 30);
        bzero(version, 100);
        bzero(cgiargs, 100);
        bzero(uri, 200);
        fclose(stream);
        close(socket);
        return;
      }
    }
    multipartparser_callbacks callbacks;
    multipartparser parser;
    multipartparser_callbacks_init(&callbacks); // It only sets all callbacks to NULL.
    callbacks.on_data = &on_data;
    multipartparser_init(&parser, boundary);
    int nparsed = multipartparser_execute(&parser, &callbacks, total, strlen(partial_body)+length);
    close(new_fd);
    server_result(stream, filename, total_read);
    bzero(method, 100);
    bzero(filename, 100);
    bzero(filetype, 30);
    bzero(version, 100);
    bzero(cgiargs, 100);
    bzero(uri, 200);
    new_fd = -1;
    fflush(stream);
    return;
  } else if (strcasecmp(method, "GET") == 0) {
    /* read (and ignore) the HTTP headers */
    /* parse the uri [crufty] */
    strncpy(cgiargs, "", strlen(""));
    bzero(filename, 100);
    strncpy(filename, ".", strlen("."));
    strncat(filename, uri, strlen(uri));
    char uri_slash[200];
    strncpy(uri_slash, uri+1, strlen(uri));
    strncat(uri_slash, "/", 1);
    if (is_dir(uri) == 0 && is_dir(uri_slash) == 0){
      /* make sure the file exists */
      if (stat(filename, &sbuf) < 0) {
	cerror(stream, filename, "404", "Not found", 
	       "Tiny couldn't find this file");
	bzero(method, 100);
	bzero(filename, 100);
	bzero(filetype, 30);
	bzero(version, 100);
	bzero(cgiargs, 100);
	bzero(uri, 200);
	fclose(stream);
	close(socket);
	return;
      }
      
      struct fatFilePointer contents = read_file(filename);
      server_result(stream, filename, contents.length);
      
      // Use mmap to return arbitrary-sized response body 
      fwrite(contents.data, 1, contents.length, stream);
      free(contents.data);
      bzero(method, 100);
      bzero(filename, 100);
      bzero(filetype, 30);
      bzero(version, 100);
      bzero(cgiargs, 100);
      bzero(uri, 200);
      fflush(stream);
    } else {
      DIR* dp = opendir(filename);
      if (dp == NULL){
	cerror(stream, method, "404", "Not Found", "Tiny does not implement this method");
	return;
      }
      int permission = 0; //add permission check here
      if (permission == 0){
	struct dirent *entry = readdir(dp);
	int numfile = 0;
	int output_size = 0;
	while (entry != NULL){
	  char* curfile = malloc(strlen(filename) + 30);
	  strcat(curfile, filename);
	  strcat(curfile, entry->d_name);
	  if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
	    numfile+= 1;
	  }
	  output_size += strlen(entry->d_name);
	  strcat(curfile, "/");
	  entry = readdir(dp);
	}
	rewinddir(dp);
	output_size += numfile;
	server_result(stream, filename, output_size);
	char** listfile = (char**) malloc(numfile * sizeof(char*));

	int index = 0;
	entry = readdir(dp);
	while (entry != NULL){
	  char* curfile = malloc(strlen(filename) + 30);
	  strcat(curfile, filename);
	  strcat(curfile, entry->d_name);
	  if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
	    listfile[index] = (char*) malloc(100);
	    struct stat st;
	    stat(entry->d_name, &st);
	    int filesize = st.st_size;
	    fwrite(entry->d_name, 1, strlen(entry->d_name), stream);
	    fwrite(";", 1, 1, stream);
	    char file_size[30];
	    sprintf(file_size, "%d", filesize);
	    //printf("file size is %s\n", file_size);
	    fwrite(file_size, sizeof(int), 1, stream);
	    fwrite("\t", 1, 1, stream);
	    fflush(stream);
	    strncpy(listfile[index], entry->d_name, strlen(entry->d_name));
	    index+= 1;
	  }
	  strcat(curfile, "/");
	  entry = readdir(dp);
	}
	fflush(stream);

	closedir(dp);
	bzero(method, 100);
        bzero(filename, 100);
        bzero(filetype, 30);
        bzero(version, 100);
        bzero(cgiargs, 100);
        bzero(uri, 200);
	return;	
      } else {
	cerror(stream, method, "403", "Forbidden", "Directory is forbidden");
	bzero(method, 100);
        bzero(filename, 100);
        bzero(filetype, 30);
        bzero(version, 100);
        bzero(cgiargs, 100);
        bzero(uri, 200);
	return;
      }
    }

  
  }
}

int handle_connection(int socket)
{
  serve_http(socket);
  return 0;
}

// Run this at  cleanup, closes server file descriptor
void cleanup() {
  if (server_fd != -1) {
    close(server_fd);
  }
}

// Main entry point for program
int main(int argc, char** argv)
{
  int socket_id;
  int client;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  struct sockaddr_in this_addr;
  struct sockaddr_in peer_addr;
  unsigned short port = 8080; /* Port to listen on */

  if(argc != 4) {
    printf("Usage: %s <port-number> <root-directory> <secret-key>\n", argv[0]);
    exit(1);
  }

  port = atoi(argv[1]);
  root = argv[2];

  strncpy(secret_key,argv[3], strlen(argv[3]));

  // We've stack allocated this_addr and peer_addr, so zero them
  // (since we wouldn't know what was there otherwise).
  memset(&this_addr, 0, addrlen );
  memset(&peer_addr, 0, addrlen );

  // Set input port
  this_addr.sin_port        = htons(port);
  // Say that we want internet traffic
  this_addr.sin_family      = AF_INET;
  // Accept connections to all IP addresses assigned to this machine
  this_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // Actually get us a socket that will listen for internet
  // connections
  socket_id = socket( AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (setsockopt(socket_id, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
    logmsg("setsockopt(SO_REUSEADDR) failed");
    exit(1);
  }

  // Set that socket up using the configuration we specified
  if (bind(socket_id, (const struct sockaddr *) &this_addr, addrlen) != 0) {
    logmsg("bind failed!");
    exit(1);
  }

  // Listen for connections on this socket
  if (listen(socket_id, 5) != 0) {
    logmsg("listen failed!");
    exit(1);
  }

  printf("There's a server running on port %d.\n", port);

  // Loop forever while there is a connection
  while((client = accept(socket_id, (struct sockaddr *) &peer_addr,
			 &addrlen)) != -1) {
    printf("Got a connection on port %d, handling now.\n", port);
    handle_connection(client);
    bzero(buffer, BUFLEN);
    close(client);
  }

  return 0;
}
