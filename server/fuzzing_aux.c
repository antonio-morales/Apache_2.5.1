
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <math.h>
#include <sys/termios.h>
#include <ev.h>
#include <sys/types.h>

#include <errno.h>
#include <unistd.h>
#include <math.h>

#include <dirent.h>

#include <execinfo.h>

#include "fuzzing_aux.h"



int clean_directory(const char *path) {
   DIR *d = opendir(path);
   size_t path_len = strlen(path);
   int r = -1;

   if (d) {
      struct dirent *p;

      r = 0;
      while (!r && (p=readdir(d))) {
          int r2 = -1;
          char *buf;
          size_t len;

          /* Skip the names "." and ".." as we don't want to recurse on them. */
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
             continue;

          len = path_len + strlen(p->d_name) + 2;
          buf = malloc(len);

          if (buf) {
             struct stat statbuf;

             snprintf(buf, len, "%s/%s", path, p->d_name);
             if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode))
                   r2 = clean_directory(buf);
                else
                   r2 = unlink(buf);
             }
             free(buf);
          }
          r = r2;
      }
      closedir(d);
   }

   return r;
}

int selfconnect(char* address, int port, char mpm){


	int tmp;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;

	void *ContentLengthStr;
	uint ContentLengthSize;
	uint numCharacters;
	void *delimiter;
	void *eoreq;
	void *eol;
	void *start_ptr;
	unsigned char filetmp[MAX_INPUT_SIZE];

    char errmsg[1024];
	struct timeval tv;

    uint8_t buf[65536];
    ssize_t length = 0;

	clean_directory("/home/antonio/Downloads/httpd-trunk/install/logs/cache");


	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\nSocket creation failed \n");
		return -1;
	}

	fuzzingFD = sock;

	if(access(inputFile, F_OK) == -1){
		printf("error accessing input file: %s\n", inputFile);
        perror("Error: ");
		return -1;
	}

	fd_inputFile = open(inputFile , O_RDONLY );

	filesize = lseek(fd_inputFile, 0L, SEEK_END);
	lseek(fd_inputFile, 0L, SEEK_SET);

	if(filesize > MAX_INPUT_SIZE)
		return -1;

	read(fd_inputFile, filedata, filesize);

	//Recalculate Content-Length
	start_ptr = filedata;
	ContentLengthStr = memmem(start_ptr, filesize, "Content-Length:", 15);
	while(ContentLengthStr){

		delimiter = memmem(ContentLengthStr, filesize-(ContentLengthStr-(void*)filedata), "\r\n\r\n", 4);
		if(delimiter){

			eoreq = memmem(delimiter+4, filesize-(delimiter+4-(void*)start_ptr), "\r\n\r\n", 4);

			if(eoreq)
				ContentLengthSize = eoreq-delimiter-4;
			else
				ContentLengthSize = filesize - (delimiter-(void*)start_ptr+4);

			eol = memmem(ContentLengthStr, filesize-(ContentLengthStr-(void*)start_ptr), "\r\n", 2);
			if(eol){
				memcpy(filetmp, eol, filesize-(eol-(void*)start_ptr));

				memcpy(ContentLengthStr, "Content-Length: ", 16);
				sprintf(ContentLengthStr+16, "%d", ContentLengthSize);
				if(ContentLengthSize != 0)
					numCharacters = (int)((ceil(log10(ContentLengthSize))+1)*sizeof(char))-1;

				memcpy(ContentLengthStr+16+numCharacters, filetmp, filesize-(eol-(void*)start_ptr));
				filesize = ContentLengthStr-(void*)filedata + 16 + numCharacters + filesize-(eol-(void*)filedata);
			}
		}

		start_ptr = ContentLengthStr+16;
		ContentLengthStr = memmem(start_ptr, filesize-(ContentLengthStr-(void*)filedata), "Content-Length:", 15);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, address, &serv_addr.sin_addr)<=0){
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	//tmp = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);

	tv.tv_sec = 0;
	tv.tv_usec = 10000;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	tmp = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (tmp < 0){
		printf("\nConnection Failed \n");
        perror("Error: ");
		return -1;
	}

	if(send(sock, filedata, filesize, 0) < 0){
		printf("\nSend Failed \n");
        perror("Error: ");
		return -1;
	}

	if(shutdown(sock, SHUT_WR) < 0){
		printf("\nSend Failed \n");
        perror("Error: ");
		return -1;
	}

	//mpm event
	if(mpm == 'e'){
		//while( (length = recv(sock, buf, 65536, MSG_DONTWAIT )) > 0 ){
		while( (length = recv(sock, buf, 65536, 0 )) > 0 ){
			write(STDOUT_FILENO, buf, length);
		}

		close(sock);
	}



    //fprintf(stderr, "Step_3\n");

	return 0;
}


void Write_and_close(){

    uint8_t buf[65536];
	ssize_t length = 0;

	while( (length = recv(fuzzingFD, buf, 65536, 0 )) > 0 ){
		write(STDOUT_FILENO, buf, length);
	}

	close(fuzzingFD);
}


print_trace(void){

  void *array[10];
  char **strings;
  int size, i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);
  if (strings != NULL)
  {

    printf ("Obtained %d stack frames.\n", size);
    for (i = 0; i < size; i++)
      printf ("%s\n", strings[i]);
  }

  free (strings);

  getchar();
}



