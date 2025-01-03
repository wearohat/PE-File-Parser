
//CREATED BY WEARDHAT

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1) 

typedef struct {
    uint16_t e_magic;    //Magic number
    uint16_t e_cblp;     //Bytes on last page of file
    uint16_t e_cp;       //Pages in file
    uint16_t e_crlc;     //Relocations
    uint16_t e_cparhdr;  //Size of header in paragraphs
    uint16_t e_minalloc; //Minimum extra paragraphs needed
    uint16_t e_maxalloc; //Maximum extra paragraphs needed
    uint16_t e_ss;       //Initial (relative) SS
    uint16_t e_sp;       //Initial SP
    uint16_t e_csum;     //Checksum
    uint16_t e_ip;       //Initial IP
    uint16_t e_cs;       //Initial (relative) CS
    uint16_t e_lfarlc;   //File address of relocation table
    uint16_t e_ovno;     //Overlay number
    uint16_t e_res[4];   //Reserved words
    uint16_t e_oemid;    //OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  //OEM information; e_oemid specific
    uint16_t e_res2[10]; //Reserved words
    uint32_t e_lfanew;   //File address of new exe header
} IMAGE_DOS_HEADER;

#define IMAGE_NT_SIGNATURE 0x00004550 

typedef struct {
    uint16_t Machine;                 
    uint16_t NumberOfSections;        
    uint32_t TimeDateStamp;           
    uint32_t PointerToSymbolTable;    
    uint32_t NumberOfSymbols;         
    uint16_t SizeOfOptionalHeader;    
    uint16_t Characteristics;         
} IMAGE_FILE_HEADER;

//PE Optional Header (standard fields)
typedef struct {
    uint16_t Magic;                   
    uint8_t MajorLinkerVersion;       
    uint8_t MinorLinkerVersion;       
    uint32_t SizeOfCode;              
    uint32_t SizeOfInitializedData;   
    uint32_t SizeOfUninitializedData; 
    uint32_t AddressOfEntryPoint;     
    uint32_t BaseOfCode;              
    uint32_t BaseOfData;              
    uint32_t ImageBase;               
    uint32_t SectionAlignment;        
    uint32_t FileAlignment;           
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;           
    uint32_t SizeOfHeaders;         
    uint32_t CheckSum;               
    uint16_t Subsystem;               
    uint16_t DllCharacteristics;      
    uint32_t SizeOfStackReserve;      
    uint32_t SizeOfStackCommit;       
    uint32_t SizeOfHeapReserve;      
    uint32_t SizeOfHeapCommit;       
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;    
} IMAGE_OPTIONAL_HEADER;

typedef struct {
    uint8_t Name[8];                  
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;          
    uint32_t SizeOfRawData;          
    uint32_t PointerToRawData;        
    uint32_t PointerToRelocations;     
    uint32_t PointerToLinenumbers;    
    uint16_t NumberOfRelocations;      
    uint16_t NumberOfLinenumbers;      
    uint32_t Characteristics;           
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

void print_file_header(IMAGE_FILE_HEADER *file_header) {
    printf("File Header:\n");
    printf("  Machine: 0x%X\n", file_header->Machine);
    printf("  Number of Sections: %d\n", file_header->NumberOfSections);
    printf("  Time Date Stamp: %u\n", file_header->TimeDateStamp);
    printf("  Characteristics: 0x%X\n", file_header->Characteristics);
}

void print_optional_header(IMAGE_OPTIONAL_HEADER *optional_header) {
    printf("Optional Header:\n");
    printf("  Image Base: 0x%X\n", optional_header->ImageBase);
    printf("  Entry Point: 0x%X\n", optional_header->AddressOfEntryPoint);
    printf("  Section Alignment: %u\n", optional_header->SectionAlignment);
    printf("  File Alignment: %u\n", optional_header->FileAlignment);
    printf("  Subsystem: 0x%X\n", optional_header->Subsystem);
    printf("  Size of Image: 0x%X\n", optional_header->SizeOfImage);
    printf("  Size of Headers: %u\n", optional_header->SizeOfHeaders);
}

void print_section_headers(FILE *file, IMAGE_FILE_HEADER *file_header) {
    IMAGE_SECTION_HEADER section_header;
    printf("Section Headers:\n");
    for (int i = 0; i < file_header->NumberOfSections; i++) {
        fread(&section_header, sizeof(section_header), 1, file);
        
        section_header.Name[7] = '\0'; 
        
        printf("  Section %d:\n", i + 1);
        printf("    Name: %.8s\n", section_header.Name);
        printf("    Virtual Address: 0x%X\n", section_header.VirtualAddress);
        printf("    Size of Raw Data: %u\n", section_header.SizeOfRawData);
        printf("    Pointer to Raw Data: 0x%X\n", section_header.PointerToRawData);
        printf("    Characteristics: 0x%X\n", section_header.Characteristics);
    }
}

void parse_pe(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "Error: File is too small to be a valid PE file.\n");
        fclose(file);
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(dos_header), 1, file);

    if (dos_header.e_magic != 0x5A4D) { // "MZ"
        fprintf(stderr, "Not a valid PE file: Invalid DOS header\n");
        fclose(file);
        return;
    }

    if (file_size < dos_header.e_lfanew + sizeof(uint32_t)) {
        fprintf(stderr, "Error: File is too small to contain PE header.\n");
        fclose(file);
        return;
    }


    fseek(file, dos_header.e_lfanew, SEEK_SET);


    uint32_t pe_signature;
    fread(&pe_signature, sizeof(pe_signature), 1, file);


    if (pe_signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file: Invalid PE signature\n");
        fclose(file);
 return;
    }

    printf("Valid PE file: %s\n", filename);
    printf("DOS Header Magic: MZ\n");
    printf("PE Signature: PE\n");

    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(file_header), 1, file);
    print_file_header(&file_header);

    IMAGE_OPTIONAL_HEADER optional_header;
    fread(&optional_header, sizeof(optional_header), 1, file);
    print_optional_header(&optional_header);

    print_section_headers(file, &file_header);

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }
    parse_pe(argv[1]);
    return 0;
}