#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void sigusr2() 
{
	if( seteuid(0) < 0 || setuid(0) < 0) {
		printf("error: didn't work\n");
		exit(-1);
	}
	else {		
		char * const command[] = {NULL};
		
		execve("/bin/sh", command, NULL);
	}
}


int main(void)
{
	signal(SIGUSR2, sigusr2);
	
	kill(getpid(), 12);
	
	sleep(1);
	return(0);	
}
