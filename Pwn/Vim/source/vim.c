#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include"SECCOMP.h"

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(mprotect),
  Allow(rt_sigreturn),
  Allow(brk),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

char *chunks[0x5];

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
    perror("Seccomp Error");
    exit(1);
  }
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1){
    perror("Seccomp Error");
    exit(1);
  }
  return;
}

void my_read(char *buffer, unsigned int size)
{
	if(read(0,buffer,size)<=0) {
		printf("No\n");
		exit(0x1337);
	}
	if(buffer[size-1] == '\n') {
		buffer[size-1] = '\x00';
	}
}

long int readnumber()
{
	char buff[0x10];
	read(0,buff,10);
	return atoll(buff);
}

void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	apply_seccomp();
}

void edit()
{
	puts("No\n");
}

void delete()
{
	unsigned int index;
	printf("Enter chunk index: ");
	index = readnumber();
	if(index >= 5 || !chunks[index]) {
		printf("No\n");
		exit(0x1337);
	}
	free(chunks[index]);
	chunks[index]=NULL;
}

void view()
{
	puts("No\n");
}

void allocate()
{
	unsigned int size;
	int i;
	for(i=0;i<5;i++) {
		if(!chunks[i])
			break;
	}
	if(i>=5){
		puts("No\n");
		exit(0x1337);
	}
	printf("Enter the size of the chunk: ");
	size = readnumber();
	if((char)size > 0x78) {
		printf("No\n");
		return ;
	}
	chunks[i] = (char *)malloc((char)size);
	printf("Enter note: ");
	my_read(chunks[i],size);
}

void print()
{
	printf("================\n");
	printf("1. Write.\n");
	printf("2. Erase.\n");
	printf("3. View.\n");
	printf("4. Edit.\n");
	printf("5. Exit.\n");
	printf("===============\n");
	printf("Choice: ");
}

int main()
{
	char buff[0x10];
	unsigned int choice;
	initialize();
	while(1) {
		print();
		choice = readnumber();
		switch(choice) {
		case 1:
			allocate();
			break;
		case 2:
			delete();
			break;
		case 3:
			view();
			break;
		case 4:
			edit();
			break;
		case 5:
			exit(0);
			break;
		case 0x1337:
			printf("Sign your name into the record book: ");
			read(0,buff,0x10);
			break;
		default:
			printf(":(\n");
			break;
		}
	}
}
