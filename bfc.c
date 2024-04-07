#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "peheader.h"

typedef struct {
    int size;
    int ep;
    unsigned char* _buf;
} BUFFER;

typedef struct {
    int max;
    int size;
    int* ptr;
} ISTACK;

BUFFER* newBuffer(){
    BUFFER* buf = malloc(sizeof(BUFFER));
    if(!buf){
        return NULL;
    }
    buf->_buf = malloc(0x400);
    if(!buf->_buf){
        free(buf);
        return NULL;
    }
    buf->size = 0x400;
    buf->ep = 0;
    return buf;
}

int extendBuffer(BUFFER* buf){
    unsigned char* newptr = realloc(buf->_buf, buf->size * 2);
    if(!newptr){
        return 0;
    }
    buf->_buf = newptr;
    buf->size *= 2;
    return 1;
}

int writeBuffer(BUFFER* buf, const unsigned char* str, int size){
    if(buf->size < buf->ep + size){
        if(!extendBuffer(buf)){
            return 0;
        }
    }
    for(int i = 0; i < size; i++){
        buf->_buf[buf->ep++] = *str++;
    }
    return size;
}

ISTACK* newIstack(){
    ISTACK* stack = malloc(sizeof(ISTACK));
    if(!stack){
        return NULL;
    }
    stack->ptr = malloc(sizeof(int) * 1024);
    if(!stack->ptr){
        free(stack);
        return NULL;
    }
    stack->size = 0;
    stack->max = 1024;
}

int extendIstack(ISTACK* stack){
    int* newptr = realloc(stack->ptr, stack->max * 2);
    if(!newptr){
        return 0;
    }
    stack->ptr = newptr;
    stack->max *= 2;
    return 1; 
}

int pushIstack(ISTACK* stack, int val){
    if(stack->max <= stack->size){
        if(!extendIstack(stack)){
            return 0;
        }
    }
    stack->ptr[stack->size++] = val;
    return 1;
}

int popIstack(ISTACK* stack){
    if(stack->size > 0){
        return stack->ptr[--stack->size];
    }
    return 0;
}

const char* progname;

void showHelp(){
    printf( "BrainF**k Compiler\n"
            "Usage: %s [-o outfile] infile\n", progname);
}

int main(int argc, char** argv){
    progname = argv[0];
    const char* infile = NULL;
    const char* outfile = "a.exe";

    if(argc < 2){
        showHelp();
        return 1;
    }

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i],"-o") == 0){
            if(++i < argc){
                outfile  = argv[i];
            }
        }else{
            infile = argv[i];
        }
    }

    if(!infile){
        showHelp();
        return 1;
    }

    FILE* srcfp = fopen(infile, "rb");
    if(!srcfp){
        printf("\"%s\" could not be opened\n", infile);
        return 1;
    }
    

    const IMAGE_DOS_HEADER doshdr = {
        .e_magic = 'M' + 'Z'*0x100,
        .e_lfanew = sizeof(IMAGE_DOS_HEADER)
    };

    IMAGE_NT_HEADERS32 hdr = {
        .Signature = 'P' + 'E'*0x100,
        .FileHeader = {
            .Machine = 0x014c,
            .NumberOfSections = 0,
            .TimeDateStamp = 0,
            .PointerToSymbolTable = 0,
            .NumberOfSymbols = 0,
            .SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32),
            .Characteristics = 0x030f
        },
        .OptionalHeader = {
            .Magic = 0x10b,
            .MajorLinkerVersion = 0,
            .MinorLinkerVersion = 0,
            .SizeOfCode = 0,
            .SizeOfInitializedData = 0,
            .SizeOfUninitializedData = 0,
            .AddressOfEntryPoint = 0,
            .BaseOfCode = 0,
            .BaseOfData = 0,
            .ImageBase = 0x00400000,
            .SectionAlignment = 0x1000,
            .FileAlignment = 0x200,
            .MajorOperatingSystemVersion = 4,
            .MinorOperatingSystemVersion = 0,
            .MajorImageVersion = 0,
            .MinorImageVersion = 0,
            .MajorSubsystemVersion = 4,
            .MinorSubsystemVersion = 0,
            .Win32VersionValue = 0,
            .SizeOfImage = 0,
            .SizeOfHeaders = 0x200,
            .CheckSum = 0,
            .Subsystem = 3,
            .DllCharacteristics = 0,
            .SizeOfStackReserve = 0x100000,
            .SizeOfStackCommit = 0x1000,
            .SizeOfHeapReserve = 0x100000,
            .SizeOfHeapCommit = 0x1000,
            .LoaderFlags = 0,
            .NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
            .DataDirectory = {
                [1] = {
                    .VirtualAddress = 0,
                    .Size = 0x28
                },
                [12] = {
                    .VirtualAddress = 0,
                    .Size = 0x8
                }
            }
        }
    };

    hdr.FileHeader.NumberOfSections = 3;
    IMAGE_SECTION_HEADER sections[3] = {
        {
            .Name = {'.', 't', 'e', 'x', 't'},
            .Misc.VirtualSize = 0x0,
            .VirtualAddress = 0x1000,
            .SizeOfRawData = 0,
            .PointerToRawData = 0x200,
            .NumberOfRelocations = 0,
            .NumberOfLinenumbers = 0,
            .Characteristics = 0x60000020
        },
        {
            .Name = ".data",
            .Misc.VirtualSize = 0,
            .VirtualAddress = 0,
            .SizeOfRawData = 0x200,
            .PointerToRawData = 0,
            .Characteristics = 0xC0000040
        },
        {
            .Name = {'.', 'b', 's', 's'},
            .Misc.VirtualSize = 0x8000,
            .VirtualAddress = 0,
            .SizeOfRawData = 0,
            .PointerToRawData = 0,
            .Characteristics = 0xc0000040
        }
    };

    // IMAGE_IMPORT_DESCRIPTOR importdscs[2] = {
    //     {
    //         DUMMYUNIONNAME.OriginalFirstThunk = 0,
    //         .TimeDateStamp = 0,
    //         .ForwarderChain = 0,
    //         .Name = 0,
    //         .FirstThunk = 0
    //     },
    //     {
    //         0
    //     }
    // };

    unsigned char import[0x200] = {
        0x30, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x20, 0x00, 0x00,
        0x28, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x43, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'm' , 's' , 'v' , 'c' , 'r' , 't' , '.' , 'd' ,
        'l' , 'l' , 0x00, 0x00, 0x00, 'p' , 'u' , 't' , 'c' , 'h' , 'a' , 'r' , 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    
    BUFFER* buf = newBuffer();
    ISTACK* lpstarts = newIstack();
    ISTACK* prints = newIstack();

    writeBuffer(buf, (unsigned char[5]){0xb9}, 5); //mov ecx, imm32
    int addrtodata = buf->ep - 4;
    while(!feof(srcfp)){
        char c = getc(srcfp);
        switch(c){
            case '+':
                // puts("wrote +");
                writeBuffer(buf, (unsigned char[]){0xfe, 0x01}, 2);
                break;
            case '-':
                // puts("wrote -");
                writeBuffer(buf, (unsigned char[]){0xfe, 0x09}, 2);
                break;
            case '>':
                // puts("wrote >");
                writeBuffer(buf, (unsigned char[]){0x41}, 1);
                break;
            case '<':
                // puts("wrote <");
                writeBuffer(buf, (unsigned char[]){0x49}, 1);
                break;
            case '[':
                // puts("wrote [");
                //xor edx, edx; mov dl, BYTE PTR [ecx]; or edx, edx; jz loopend
                writeBuffer(buf, (unsigned char[12]){0x31, 0xd2, 0x8a, 0x11, 0x09, 0xd2, 0x0f, 0x84}, 12);
                pushIstack(lpstarts, buf->ep - 4);
                break;
            case ']':
                // puts("wrote ]");
                // xor edx, edx; mov dl, BYTE PTR [ecx]; or edx, edx; jnz loopstart
                writeBuffer(buf, (unsigned char[12]){0x31, 0xd2, 0x8a, 0x11, 0x09, 0xd2, 0x0f, 0x85}, 12);
                int addrstart = popIstack(lpstarts);
                *(int*)&buf->_buf[addrstart] = buf->ep - 4 - addrstart;
                *(int*)&buf->_buf[buf->ep - 4] = addrstart - (buf->ep - 4);
                break;
            case '.':
                // puts("wrote .");
                writeBuffer(buf, (unsigned char[]){0x51}, 1);//push ecx;
                //xor edx, edx; mov dl, BYTE PTR [ecx]; push edx; call rel32;
                writeBuffer(buf, (unsigned char[10]){0x31, 0xd2, 0x8a, 0x11, 0x52, 0xe8}, 10);
                pushIstack(prints, buf->ep - 4);
                writeBuffer(buf, (unsigned char[]){0x83, 0xc4, 0x04}, 3);//add esp, 4
                writeBuffer(buf, (unsigned char[]){0x59}, 1);//pop ecx;
                break;
            default:
                break;
        }
    }


    //xor eax,eax; ret;
    writeBuffer(buf, (unsigned char[]){0x31, 0xc0, 0xc3}, 3);

    // printf("codesize:%d\n", buf->ep);
    // for(int i = 0; i < buf->ep; i++){
    //     printf("%hhx, ", buf->_buf[i]);
    // }
    // putchar('\n');

    while(prints->size){
        // printf("prints->size:%d\n", prints->size);
        int addr = popIstack(prints);
        *(int*)&buf->_buf[addr] = buf->ep - addr - 4;
    }
    // puts("debug");

    writeBuffer(buf, (unsigned char[]){0xff, 0x25}, 2);
    int addrputc = buf->ep;
    writeBuffer(buf, (unsigned char[4]){0}, 4);



    unsigned char* code = buf->_buf;
    int codesize = buf->ep;

    // printf("codesize:%d\n", codesize);
    // for(int i = 0; i < codesize; i++){
    //     printf("%hhx, ", buf->_buf[i]);
    // }

    sections[0].Misc.VirtualSize = codesize;
    sections[0].SizeOfRawData = (codesize+hdr.OptionalHeader.FileAlignment-1)/hdr.OptionalHeader.FileAlignment*hdr.OptionalHeader.FileAlignment;

    sections[1].PointerToRawData = 0x200 + sections[0].SizeOfRawData;
    sections[1].VirtualAddress = sections[0].VirtualAddress
        + (codesize+hdr.OptionalHeader.SectionAlignment-1)/hdr.OptionalHeader.SectionAlignment*hdr.OptionalHeader.SectionAlignment;

    sections[2].VirtualAddress = sections[1].VirtualAddress + 0x1000;

    hdr.OptionalHeader.DataDirectory[1].VirtualAddress = sections[1].VirtualAddress;
    hdr.OptionalHeader.DataDirectory[2].VirtualAddress = sections[1].VirtualAddress + 0x28;

    hdr.OptionalHeader.SizeOfImage = 0x1000 
        + (codesize+hdr.OptionalHeader.SectionAlignment-1)/hdr.OptionalHeader.SectionAlignment*hdr.OptionalHeader.SectionAlignment
        + 0x1000
        + 0x8000;
    hdr.OptionalHeader.SizeOfCode = sections[0].SizeOfRawData;
    hdr.OptionalHeader.AddressOfEntryPoint = 0x1000;
    hdr.OptionalHeader.BaseOfCode = 0x1000;

    *(int*)&buf->_buf[addrtodata] = hdr.OptionalHeader.ImageBase + sections[2].VirtualAddress;
    *(int*)&buf->_buf[addrputc] = hdr.OptionalHeader.ImageBase + sections[1].VirtualAddress + 0x28;

    FILE* dstfp = fopen(outfile, "wb");
    fwrite(&doshdr, sizeof(doshdr), 1, dstfp);
    fwrite(&hdr, sizeof(hdr), 1, dstfp);
    fwrite(sections, sizeof(sections), 1, dstfp);

    fseek(dstfp, 0x200, SEEK_SET);

    fwrite(code, codesize, 1, dstfp);

    fseek(dstfp, sections[1].PointerToRawData, SEEK_SET);

    fwrite(import, sizeof(import), 1, dstfp);
    
    fclose(srcfp);
    fclose(dstfp);

    return 0;
}