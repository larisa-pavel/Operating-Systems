/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "exec_parser.h"
static int fd;
static so_exec_t *exec;
static struct sigaction lovely_handler;
static int mapped[1000][1000];

static void segv_handler (int signum, siginfo_t *info, void *context)
{
	int i;

	//cu i parcurg segmentele
	for (i = 0; i < exec->segments_no ; i++) {
		void *base_addr = (void *)exec->segments[i].vaddr;

		if (info->si_addr <= base_addr+exec->segments[i].mem_size && info->si_addr >= base_addr) {
			uintptr_t index = (info->si_addr-base_addr)/4096;

			//index reprezinta numarul paginii, pe care l-am calculat ca diferenta dintre
			//adresa de pagefault si adresa de baza, impartit la numarul de biti al unei pagini.
			if (mapped[i][index] == 1) {
				lovely_handler.sa_sigaction(signum, info, context);
				return;
			}
			//verific daca pagina din segmentul din care face parte adresa page fault-ului a fost mapata
			void *page_start = base_addr+(index*4096);

			//page_start este adresa unde incepe pagina unde se afla page fault ul
			void *new_addr = mmap(page_start, 4096, PROT_WRITE|PROT_READ, MAP_FIXED | MAP_PRIVATE
					, fd, exec->segments[i].offset+index*4096);
			//mapez pagina la care se afla page fault-ul, ii dau permisiuni de read si write, si folosesc
			//flag-ul MAP_FIXED pentru a mapa exact portiunea dorita, iar cu flag-ul MAP_PRIVATE creez
			//o mapare privata de tip copy-on-write
			unsigned int file_size = exec->segments[i].file_size;

			mapped[i][index] = 1;
			//am notat pagina segmentului in care se afla page fault-ul ca fiind mapata
			if (file_size < (index+1)*4096 && file_size >= index*4096)
				memset(base_addr+file_size, 0, (index+1)*4096-file_size);
			//daca file_size-ul se afla in interiorul paginii, zeroizez
			//diferenta intre spatiul din memorie si spatiul din fisier
			if (file_size < index*4096)
				memset(page_start, 0, 4096);
			//daca filse_size-ul se afla inaintea paginii, zeroizez toata pagina
			//iar cazul in care file_size-ul se afla dupa pagina, nu zeroizez nimic
			mprotect(new_addr, 4096, exec->segments[i].perm);
			//setez permisiunile pe pagina mapata
			return;
		}
	}
	lovely_handler.sa_sigaction(signum, info, context);
	//daca adresa de page fault se afla inafara segmentelor, atunci apelez handlerul default
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, &lovely_handler);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	fd = open(path, O_RDWR);
	so_start_exec(exec, argv);

	return -1;
}
