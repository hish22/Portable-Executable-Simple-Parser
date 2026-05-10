#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
    This C program is a Portable Executable (PE) 
    parser that extracts metadata from Windows binaries. 
    It reads the MS-DOS header to find the file's entry point, 
    then jumps to the COFF header to identify the target architecture 
    (x86, x64, or ARM64) and the number of file sections. 
    By decoding the internal timestamp and "Magic" values, 
    it displays when the file was compiled and whether it is a 32-bit (PE32) 
    or 64-bit (PE32+) executable.
*/

struct dos_section {
    short magic_head; // 2 bytes
    char padding[58]; // 58 bytes
    int p_to_pe_head; // 4 bytes
};

struct portable_executable {
    int signature; // (4 bytes)
    unsigned short machine; // (2 bytes)
    short numberOfSections; // (2 bytes)
    int timeDateStamp; // (4 bytes)
    int deprecatedPpt; // (4 bytes)
    int deprecatedNost; // (4 bytes)
    short SizeOfOptionalHeader; // (2 bytes)
    short characteristics; // (2 bytes)
    unsigned short magic; // (2 bytes)
};

int main(int argc,char **argv) {

    // Request file name
    if (argc != 2) {
        printf("Input file of type (PE) -> %s filename\n",argv[0]);
        exit(1);
    }

    // Create a new dos block (64 bytes without count of the padding)
    struct dos_section *dptr = malloc(sizeof(struct dos_section));

    // Create PE new block (26 bytes without count of the padding)
    struct portable_executable *pptr = malloc(sizeof(struct portable_executable));

    // Copy content from disk to memory block
    FILE *fh = fopen(argv[1],"rb");

    if (fh != NULL) {
        fread(dptr, sizeof(struct dos_section), 1, fh);
        fseek(fh, dptr->p_to_pe_head, SEEK_SET);
        fread(pptr, sizeof(struct portable_executable), 1, fh);
        fclose(fh);
    }

    // DOS SIGNATURE HEADER
    unsigned char *magic_head = (unsigned char*) &dptr->magic_head;
    printf("DOS magic header: %c%c\n",magic_head[0],magic_head[1]);

    // COFF Signature
    char *signaturePtr = (char *) &pptr->signature;
    printf("COFF header signature: %c%c (%x)\n", 
        *signaturePtr, *(signaturePtr+1), pptr->signature);

    // COFF machine
    switch (pptr->machine)
    {
    case 0x014C:
        printf("COFF header Machine: %s (%x)\n","Intel 386 or later (x86) -",pptr->machine);
        break;
    
    case 0x8664:
        printf("COFF header Machine: %s (%x)\n","x64 (AMD64/Intel 64) -",pptr->machine);
        break;

    case 0xAA64:
        printf("COFF header Machine: %s (%x)\n","ARM64 -",pptr->machine);
        break;

    default:
        printf("COFF header Machine: %c (%x)\n",pptr->machine, pptr->machine);
        break;
    }

    // COFF number of sections
    printf("COFF header numberOfSections: %x\n",pptr->numberOfSections);

    // COFF Timestamp
    time_t t = pptr->timeDateStamp;
    struct tm *info = localtime(&t);

    char buffer[80];
    // Format: 2026-05-09 15:10:45
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", info);

    printf("COFF header Timestamp: %s\n",buffer);
    
    // Standard COFF Magic
    switch (pptr->magic)
    {
    case 0x010B:
        printf("COFF magic: %s (%x)\n","PE32",pptr->magic);
        break;
    
    case 0x020B:
        printf("COFF magic: %s (%x)\n","PE32+",pptr->magic);
        break;
    
    default:
        break;
    }

    free(dptr);
    free(pptr);
    return 0;
}