# Portable-Executable-Simple-Parser

This C program is a Portable Executable (PE) parser that extracts metadata from Windows binaries. It reads the MS-DOS header to find the file's entry point, then jumps to the COFF header to identify the target architecture (x86, x64, or ARM64) and the number of file sections. By decoding the internal timestamp and "Magic" values, it displays when the file was compiled anwhether it is a 32-bit (PE32) or 64-bit (PE32+) executable.

# How to use it?

```bash
gcc pe_file_parser.c -o pfp
./pfp <filename>.exe
```