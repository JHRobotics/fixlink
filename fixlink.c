/*****************************************************************************
 MIT No Attribution

 Copyright 2023-2026 Jaroslav Hensl <emulator@emulace.cz>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 IN THE SOFTWARE.
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

const char help[] =
	"Usage: %s <mode> [--dry-run] exe_file_to_fix\n"
	"<mode> can be:\n"
	"-40: set expect Windows version to 4.0 (NE target)\n"
	"-vxd32: fix wrong paging and flags in wlink VXD (LE target)\n"
	"-shared: fix EXE/DLL to load to shared memory (PE target)\n"
	"-checksum: recalculate PE checksum (PE target)\n"
	"-relink: replace import DLL with another one, usage is:\n"
	"\t-relink tofix.exe newDLL.dll oldDLL.dll [another_old_DLL.dll [...]]\n"
	"-hint: update import ordinals to match export library, usage is:\n"
	"\t-hint [--dry-run] [--use-export-name] tofix.exe import.dll\n"
	"\n";

#pragma pack(push)
#pragma pack(1)

/* http://www.delorie.com/djgpp/doc/exe/ */
typedef struct EXE_header {
  uint16_t signature; /* == 0x5a4D */
  uint16_t bytes_in_last_block;
  uint16_t blocks_in_file;
  uint16_t num_relocs;
  uint16_t header_paragraphs;
  uint16_t min_extra_paragraphs;
  uint16_t max_extra_paragraphs;
  uint16_t ss;
  uint16_t sp;
  uint16_t checksum;
  uint16_t ip;
  uint16_t cs;
  uint16_t reloc_table_offset;
  uint16_t overlay_number;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;
} EXE_header_t;

#define EXE_SIGN 0x5a4D

/* from: https://wiki.osdev.org/NE */
typedef struct NE_header
{
	uint16_t signature;          /*"NE", 0x4543 */
	uint8_t MajLinkerVersion;    /*The major linker version */
	uint8_t MinLinkerVersion;    /*The minor linker version */
	uint16_t EntryTableOffset;   /*Offset of entry table, see below */
	uint16_t EntryTableLength;   /*Length of entry table in bytes */
	uint32_t FileLoadCRC;        /*32-bit CRC of entire contents of file */
	uint8_t ProgFlags;           /*Program flags, bitmapped */
	uint8_t ApplFlags;           /*Application flags, bitmapped */
	uint16_t AutoDataSegIndex;   /*The automatic data segment index */
	uint16_t InitHeapSize;       /*The initial local heap size */
	uint16_t InitStackSize;      /*The initial stack size */
	uint32_t EntryPoint;         /*CS:IP entry point, CS is index into segment table */
	uint32_t InitStack;          /*SS:SP initial stack pointer, SS is index into segment table */
	uint16_t SegCount;           /*Number of segments in segment table */
	uint16_t ModRefs;            /*Number of module references (DLLs) */
	uint16_t NoResNamesTabSiz;   /*Size of non-resident names table, in bytes (Please clarify non-resident names table) */
	uint16_t SegTableOffset;     /*Offset of Segment table */
	uint16_t ResTableOffset;     /*Offset of resources table */
	uint16_t ResidNamTable;      /*Offset of resident names table */
	uint16_t ModRefTable;        /*Offset of module reference table */
	uint16_t ImportNameTable;    /*Offset of imported names table (array of counted strings, terminated with string of length 00h) */
	uint32_t OffStartNonResTab;  /*Offset from start of file to non-resident names table */
	uint16_t MovEntryCount;      /*Count of moveable entry point listed in entry table */
	uint16_t FileAlnSzShftCnt;   /*File alignment size shift count (0=9(default 512 byte pages)) */
	uint16_t nResTabEntries;     /*Number of resource table entries */
	uint8_t targOS;              /*Target OS */
	uint8_t OS2EXEFlags;         /*Other OS/2 flags */
	uint16_t retThunkOffset;     /*Offset to return thunks or start of gangload area - what is gangload? */
	uint16_t segrefthunksoff;    /*Offset to segment reference thunks or size of gangload area */
	uint16_t mincodeswap;        /*Minimum code swap area size */
	uint16_t expctwinver;        /*Expected windows version eg. 0x030A, 0x0400 */
} NE_header_t;

#define NE_SIGN 0x454E

/* more source, best is here:
	https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h
 */
typedef struct LE_header
{
	uint16_t signature; /* "LX" 0x584C - 16bit or "LE" - 32bit */
	uint8_t  BOrd;
	uint8_t  WOrd;
	uint32_t Formatlevel;
	uint16_t CPUType; /* 0x08 */
	uint16_t OSType;
	uint32_t ModuleVersion;
	uint32_t ModulesFlags; /* 0x10 */
	uint32_t ModuleNumOfPages;
	uint32_t EIPObject; /* 0x18 */
	uint32_t EIP;
	uint32_t ESPObject; /* 0x20 */
	uint32_t ESP;
	uint32_t PageSize; /* 0x28 */
	uint32_t PageOffsetShift; /* 16 - offset, 32 - shift */
	uint32_t FixupSectionSize; /* 0x30 */
	uint32_t FixupSectionChecksum;
	uint32_t LoaderSectionSize; /* 0x38 */
	uint32_t LoaderSectionChecksum;
	uint32_t ObjectTableOff; /* 0x40 */
	uint32_t NumObjectsInModule;
	uint32_t ObjectPageTableOff; /* 0x48 */
	uint32_t ObjectInterPagesOff;
	uint32_t ResourceTableOffset; /* 0x50 */
	uint32_t ResourceTableEntries;
	uint32_t ResidentNameTLBOff; /* 0x58 */
	uint32_t EntryTableEntries;
	uint32_t ModulesDirectivesOff; /* 0x60 */
	uint32_t NumModuleDirectives;
	uint32_t FixupPagetableOff; /* 0x68 */
	uint32_t FixupRecordsTableOff;
	uint32_t ImportModuleTLBOff; /* 0x70 */
	uint32_t NumImportMODEntries;
	uint32_t ImportProcTlbOff; /* 0x78 */
	uint32_t PerPageChecksumOff;
	uint32_t DataPagesOffset; /* 0x80 */
	uint32_t NumPreloadPages;
	uint32_t NonResNameTLBOff; /* 0x88 */
	uint32_t NonResNameTLBLen;
	uint32_t NotResnameTLBChecksum; /* 0x90 */
	uint32_t AutoDSObject;
	uint32_t DebugInfoOff; /* 0x98 */
	uint32_t DebugInfoLength;
	uint32_t InstancePreload; /* 0xA0 */
	uint32_t InstanceDemand;
	uint32_t Heapsize; /* 0xA8 */
	uint32_t StackSize; /* OS2 only */
  union /* 0xB0 */
  {
		uint8_t Reserved[20]; /* pad to 196 bytes. */
    struct
    {
			uint8_t  ReservedVXD[8]; /* +0xB0 */
			uint32_t WinresOff;     /* +0xB8 Windows VxD version info resource offset */
			uint32_t WinresLen;     /* +0xBC Windows VxD version info resource lenght */
			uint16_t DeviceID;      /* +0xC0 Windows VxD device ID */
			uint16_t DDKversion;    /* +0xC2 Windows VxD DDK version (0x030A) */
		} vxd;
  };
} LE_header_t;

#define LE_SIGN 0x454C
#define LX_SIGN 0x584C

typedef struct LE_object
{
	uint32_t size;       /* object virtual size */
	uint32_t addr;       /* base virtual address */
	uint32_t flags;
	uint32_t mapidx;     /* page map index */
	uint32_t mapsize;    /* number of entries in page map */
	uint32_t reserved;
} LE_object_t;

#define OBJ_READABLE        0x0001
#define OBJ_WRITEABLE       0x0002
#define OBJ_EXECUTABLE      0x0004
#define OBJ_RESOURCE        0x0008
#define OBJ_DISCARDABLE     0x0010
#define OBJ_SHARABLE        0x0020
#define OBJ_HAS_PRELOAD     0x0040
#define OBJ_HAS_INVALID     0x0080
#define OBJ_PERM_SWAPPABLE  0x0100  /* LE */
#define OBJ_HAS_ZERO_FILL   0x0100  /* LX */
#define OBJ_PERM_RESIDENT   0x0200
#define OBJ_PERM_CONTIGUOUS 0x0300  /* LX */
#define OBJ_PERM_LOCKABLE   0x0400
#define OBJ_ALIAS_REQUIRED  0x1000
#define OBJ_BIG             0x2000
#define OBJ_CONFORMING      0x4000
#define OBJ_IOPL            0x8000

typedef struct LE_map_entry
{
	uint8_t page_num[3]; /* 24-bit page number in .exe file */
	uint8_t flags;
} LE_map_entry_t;

/*
 * PE Documentation here:
 *  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 *
 * PE checksum algorithm:
 *  https://bytepointer.com/resources/microsoft_pe_checksum_algo_distilled.htm
 *
 * Discussion about PE checksum (list of examples how don't do it):
 *  https://stackoverflow.com/questions/6429779/can-anyone-define-the-windows-pe-checksum-algorithm
 *
 */
typedef struct PE_signature
{
	uint16_t signature;
	uint16_t zero;
} PE_signature_t;

#define PE_SIGN 0x4550

typedef struct COFF_header
{
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
} COFF_header_t;

typedef struct PE_header
{
	/* Header Standard Fields */
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	/* Header Windows-Specific Fields */
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
} PE_header_t;

typedef struct PE_section
{
	uint8_t  Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} PE_section_t;

#define PE32 0x10b
#define IMAGE_FILE_MACHINE_I386 0x14c
#define SIZE_OF_PE32 224

#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000

typedef struct PE_image_directory
{
	uint32_t VirtualAddress;
	uint32_t Size;
} PE_image_directory_t;

typedef struct PE_image_directories
{
	PE_image_directory_t ExportTable;
	PE_image_directory_t ImportTable;
	PE_image_directory_t ResourceTable;
	PE_image_directory_t ExceptionTable;
	PE_image_directory_t CertificateTable;
	PE_image_directory_t BaseRelocationTable;
	PE_image_directory_t Debug;
	PE_image_directory_t Architecture;
	PE_image_directory_t GlobalPtr;
	PE_image_directory_t TLSTable;
	PE_image_directory_t LoadConfigTable;
	PE_image_directory_t BoundImport;
	PE_image_directory_t IAT;
	PE_image_directory_t DelayImportDescriptor;
	PE_image_directory_t CLRRuntimeHeader;
	PE_image_directory_t Reserved;
} PE_image_directories_t;

#define ID_EXPORT_TABLE 1
#define ID_IMPORT_TABLE 2
#define ID_RESOURCE_TABLE 3
#define ID_EXCEPTION_TABLE 4
#define ID_CERTIFICATE_TABLE 5
#define ID_BASE_RELOCATION_TABLE 6

typedef struct PE_idata_idt
{
	uint32_t rva_import_lookup_table;
	uint32_t timestamp;
	uint32_t forwarder_chain; 
	uint32_t rva_dllname;
	uint32_t rva_import_address_table;
} PE_idata_idt_t;

#define ILT_IS_ORDINAL 0x80000000

typedef struct PE_hint_name_table
{
	uint16_t hint;
	char name[1]; /* variable length word padded */
} PE_hint_name_table_t;

typedef struct PE_edata_edt
{
	uint32_t flags; /* Reserved, must be 0. */
	uint32_t timestamp; /* The time and date that the export data was created. */
	uint16_t major; /* The major version number. The major and minor version numbers can be set by the user. */
	uint16_t minor; /* The minor version number. */
	uint32_t rva_dllname; /*	The address of the ASCII string that contains the name of the DLL. This address is relative to the image base. */
	uint32_t ordinal_base; /* The starting ordinal number for exports in this image. This field specifies the starting ordinal number for the export address table. It is usually set to 1. */
	uint32_t address_table_entries; /* The number of entries in the export address table. */
	uint32_t number_of_name_pointers; /* The number of entries in the name pointer table. This is also the number of entries in the ordinal table. */
	uint32_t rva_export_address_table; /*	The address of the export address table, relative to the image base. */
	uint32_t rva_name_pointer; /*	The address of the export name pointer table, relative to the image base. The table size is given by the Number of Name Pointers field. */
	uint32_t rva_ordinal_table; /*	The address of the ordinal table, relative to the image base. */
} PE_edata_edt_t;

#pragma pack(pop)

/* error codes */
#define OK           0
#define ERROR_OPEN  -1
#define ERROR_READ -2
#define ERROR_WRITE -3
#define ERROR_SEEK  -4
#define ERROR_NOT_MZ  -5
#define ERROR_NOT_NE  -6
#define ERROR_NOT_LE  -7
#define ERROR_NOT_PE  -8
#define ERROR_LOW_BASE -9
#define ERROR_NOT_PE32  -10
#define ERROR_NOT_PE_I386 -11
#define ERROR_NO_FILE -12
#define ERROR_NO_SECTION -13
#define ERROR_MALLOC -14
#define ERROR_TOO_MANY_DLL -15
#define ERROR_NEED_1_AND_MORE_FILES -16
#define ERROR_NEED_2_AND_MORE_FILES -16

typedef struct error_msg
{
	int code;
	const char *txt;
} error_msg_t;

error_msg_t error_msg_table[] = {
	{ERROR_OPEN,  "Cannot open file!"},
	{ERROR_READ,  "File read failed! (wrong or corrupted file)"},
	{ERROR_WRITE, "File write failed! (readonly/locked file or readonly medium)"},
	{ERROR_SEEK,  "Seek failed! (wrong or corrupted file)"},
	{ERROR_NOT_MZ, "Can't find MZ header! (DOS compatibility header corruped or missing)"},
	{ERROR_NOT_NE, "File is not New Executable (NE, *.drv)!"},
	{ERROR_NOT_LE, "File is not 32bit Linear Executable (LE, *.vxd)!"},
	{ERROR_NOT_PE, "File in not Portable Executable (PE, *.exe, *.dll)!"},
	{ERROR_LOW_BASE, "Image base must be >= 0x80000000 to load to shared space!"},
	{ERROR_NOT_PE32, "Wrong PE version, PE32 required!"},
	{ERROR_NOT_PE_I386, "EXE file architecture in not i386!"},
	{ERROR_NO_FILE, "No file specified"},
	{ERROR_NO_SECTION, "section not found in PE file!"},
	{ERROR_MALLOC, "cannot allocate memory"},
	{ERROR_TOO_MANY_DLL, "To much DLL on command line"},
	{ERROR_NEED_1_AND_MORE_FILES, "This command need additional 1 file"},
	{ERROR_NEED_1_AND_MORE_FILES, "This command need additional 2 or more files"},
	{0, NULL}
};

long EXE_offset(FILE *f, EXE_header_t *outEXE)
{
	long offset = 0;
	if(fread(outEXE, sizeof(EXE_header_t), 1, f) == 1)
	{
		if(outEXE->signature == EXE_SIGN)
		{
			if(outEXE->e_lfanew == 0)
			{
				offset = outEXE->blocks_in_file * 512;
				if(outEXE->bytes_in_last_block)
				{
					offset -= (512 - outEXE->bytes_in_last_block);
				}
			}
			else
			{
				offset = outEXE->e_lfanew;
			}
		}
	}
	
	return offset;
}

bool read_header(FILE *f, size_t header_size, uint16_t magic, void *out)
{
	if(fread(out, header_size, 1, f) == 1)
	{
		if(*((uint16_t*)out) == magic)
		{
			return true;
		}
	}
	return false;
}

bool read_block(FILE *f, size_t block_size, void *out)
{
	if(fread(out, block_size, 1, f) == 1)
	{
		return true;
	}
	return false;
}

bool read_move(FILE *f, size_t offset_from_begin)
{
	return fseek(f, offset_from_begin, SEEK_SET) == 0;
}

bool read_block_begin(FILE *f, long offset, size_t block_size, void *out)
{
	if(read_move(f, offset))
	{
		return read_block(f, block_size, out);
	}
	return false;
}

bool writeback_block(FILE *f, size_t block_size, void *data)
{
	long offset = ftell(f);
	
	fseek(f, offset-block_size, SEEK_SET);
	if(fwrite(data, block_size, 1, f) == 1)
	{
		fseek(f, offset, SEEK_SET);
		return true;
	}
	fseek(f, offset, SEEK_SET);

	return false;
}

void sstrcpy(void *dst, const void *src, size_t buffer_max)
{
	size_t len = strlen(src);
	if((len+1) > buffer_max)
	{
		len = buffer_max-1;
	}
	memcpy(dst, src, len);
	((uint8_t*)dst)[len] = '\0';
}

int fix_wlink_vxd(const char *file, bool dofix)
{
	EXE_header_t exe;
	LE_header_t  le;
	FILE *f;
	int rc = OK;
	long offset;
	
	f = fopen(file, "r+b");
	if(f != NULL)
	{
		offset = EXE_offset(f, &exe);
		if(offset > 0)
		{
			if(read_move(f, offset))
			{
				if(read_header(f, sizeof(LE_header_t), LE_SIGN, &le))
				{
					unsigned int i;
					for(i = 0; i < le.NumObjectsInModule; i++)
					{
						LE_object_t obj;
						uint32_t new_flags;
						if(read_block_begin(f,
							offset + le.ObjectTableOff + i*sizeof(LE_object_t),
							sizeof(LE_object_t), &obj))
						{
							printf("LE object #%d: (addr: %d, flags: %08X)", i, obj.addr, obj.flags);

							/* all VXD segments MUST be executable */
							new_flags = obj.flags | OBJ_EXECUTABLE;

							if(obj.addr != 0 || obj.flags != new_flags)
							{
								if(dofix)
								{
									obj.flags = new_flags;
									obj.addr = 0; /* VXD using flat model, so all pages must start from begining */

									if(!writeback_block(f, sizeof(LE_object_t), &obj))
									{
										rc = ERROR_WRITE;
										break;
									}

									printf(" -> (addr: %d, flags: %08X)", obj.addr, obj.flags);
								} /* dofix */
								else
								{
									printf(" != (addr: 0, flags: %08X)", new_flags);
								}
							} /* needfix */
							
							printf("\n");							
						}
						else
						{
							rc = ERROR_READ;
							break;
						}
					} /* for */
				} else rc = ERROR_NOT_LE;
			} else rc = ERROR_READ;
		} else rc = ERROR_NOT_MZ;

		fclose(f);
	} else rc = ERROR_OPEN;

	return rc;
}

int fix_wlink_drv(const char *file, uint16_t new_expctwinver, bool dofix)
{
	EXE_header_t exe;
	NE_header_t   ne;
	FILE *f;
	int rc = OK;
	long offset;
	
	f = fopen(file, "r+b");
	if(f != NULL)
	{
		offset = EXE_offset(f, &exe);
		if(offset > 0)
		{
			if(read_move(f, offset))
			{
				if(read_header(f, sizeof(NE_header_t), NE_SIGN, &ne))
				{
					printf("NE.expctwinver = %04X", ne.expctwinver);
					if(ne.expctwinver != new_expctwinver)
					{
						ne.expctwinver = new_expctwinver;
						if(dofix)
						{
							if(!writeback_block(f, sizeof(NE_header_t), &ne))
							{
								rc = ERROR_WRITE;
							}
							printf(" -> %04X", ne.expctwinver);
						} /* dofix */
						else
						{
							printf(" != %04X", ne.expctwinver);
						}
					} /* need fix */
					printf("\n");					
				} else rc = ERROR_NOT_NE;
			} else rc = ERROR_READ;
		} else rc = ERROR_NOT_MZ;
			
		fclose(f);
	} else rc = ERROR_OPEN;

	return rc;
}

int fix_pe_shared(const char *file, bool dofix)
{
	EXE_header_t exe;
	PE_signature_t pe_sign;
	COFF_header_t coff;
	PE_header_t pe;
	PE_section_t section;
	char section_name[9] = {0};
	
	FILE *f;
	int rc = OK;
	long offset;
	
	f = fopen(file, "r+b");
	if(f != NULL)
	{
		offset = EXE_offset(f, &exe);
		if(offset > 0)
		{
			if(read_move(f, offset))
			{
				if(read_header(f, sizeof(PE_signature_t), PE_SIGN, &pe_sign))
				{
					if(pe_sign.zero == 0)
					{
						if(read_block(f, sizeof(COFF_header_t), &coff))
						{
							if(coff.Machine == IMAGE_FILE_MACHINE_I386)
							{
								if(read_header(f, sizeof(PE_header_t), PE32, &pe))
								{
									printf("PE image base: %08X\n", pe.ImageBase);
									if(pe.ImageBase >= 0x80000000UL)
									{
										/* skip extra space which not in PE_header_t */
										if(fseek(f, SIZE_OF_PE32-sizeof(PE_header_t), SEEK_CUR) == 0)
										{
											unsigned int i;
											for(i = 0; i < coff.NumberOfSections; i++)
											{
												if(read_block(f, sizeof(PE_section_t), &section))
												{
													memcpy(section_name, section.Name, 8);
													printf("Section: %8s, flags = %08X", section_name, section.Characteristics);
													
													if(((section.Characteristics & IMAGE_SCN_MEM_SHARED) == 0)
														 /* && ((section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)*/)
													{
														if(dofix)
														{
															section.Characteristics |= IMAGE_SCN_MEM_SHARED;
															if(!writeback_block(f, sizeof(PE_section_t), &section))
															{
																rc = ERROR_WRITE;
																break;
															}
															printf(" -> %08X", section.Characteristics);
														} /* dofix */
														else
														{
															printf(" != %08X", section.Characteristics | IMAGE_SCN_MEM_SHARED);
														}
													} /* need fix */
													printf("\n");

												} else rc = ERROR_READ;
											} /* for */
										} else rc = ERROR_READ;
									} else rc = ERROR_LOW_BASE;
								} else rc = ERROR_NOT_PE32;
							} else rc = ERROR_NOT_PE_I386;
						} else rc = ERROR_READ;
					} else rc = ERROR_NOT_PE;
				} else rc = ERROR_NOT_PE;
			} else rc = ERROR_READ;
		} else rc = ERROR_NOT_MZ;

		fclose(f);
	} else rc = ERROR_OPEN;
	
	return rc;
}

/* c89 - offsetof(PE_header_t, CheckSum) */
size_t offsetof_PE_header_CheckSum()
{
	PE_header_t *h = (void*)0;
	return (size_t)&(h->CheckSum);
}

int fix_pe_checksum(const char *file, bool dofix)
{
	EXE_header_t exe;
	PE_signature_t pe_sign;
	COFF_header_t coff;
	PE_header_t pe;
	
	FILE *f;
	int rc = OK;
	long offset;
	long offset_checksum;
	
	f = fopen(file, "r+b");
	if(f != NULL)
	{
		offset = EXE_offset(f, &exe);
		if(offset > 0)
		{
			if(read_move(f, offset))
			{
				if(read_header(f, sizeof(PE_signature_t), PE_SIGN, &pe_sign))
				{
					if(pe_sign.zero == 0)
					{
						if(read_block(f, sizeof(COFF_header_t), &coff))
						{
							if(coff.Machine == IMAGE_FILE_MACHINE_I386)
							{
								if(read_header(f, sizeof(PE_header_t), PE32, &pe))
								{
									uint32_t checksum = 0;
									long fpos = 0;
									int c;

									offset_checksum = ftell(f) + offsetof_PE_header_CheckSum() - sizeof(PE_header_t);
									fseek(f, 0, SEEK_SET);
									while(!feof(f))
									{
										uint16_t word = 0;
										
										/* first byte */
										if(fpos == offset_checksum) /* ignore original checksum */
										{
											fseek(f, 4, SEEK_CUR);
											fpos += 4;
										}
										c = fgetc(f);
										if(c == EOF)
										{
											break;
										}
										else
										{
											fpos++;
										}
										word = c;
										
										/* second byte */
										if(fpos == offset_checksum) /* ignore original checksum */
										{
											fseek(f, 4, SEEK_CUR);
											fpos += 4;
										}
										c = fgetc(f);
										if(c == EOF)
										{
											c = 0; /* when is file not word aligned, assume extra byte is 0 */
										}
										else
										{
											fpos++;
										}
										word |= c << 8; /* low endian */
										
										/* update checksum */
										checksum += word;
										checksum = (checksum >> 16) + (checksum & 0xffff);
									}
									checksum = (checksum >> 16) + (checksum & 0xffff);
									checksum += fpos; /* finaly sum file size with checksum */
									
									printf("PE checksum: %08X", pe.CheckSum);
									if(pe.CheckSum != checksum)
									{
										if(dofix)
										{
											fseek(f, offset_checksum, SEEK_SET);
											fwrite(&checksum, 4, 1, f);
										
											printf(" -> %08X", checksum);
										}
										else
										{
											printf(" != %08X", checksum);
										}
									} /* need fix */
									printf("\n");
								} else rc = ERROR_NOT_PE32;
							} else rc = ERROR_NOT_PE_I386;
						} else rc = ERROR_READ;
					} else rc = ERROR_NOT_PE;
				} else rc = ERROR_NOT_PE;
			} else rc = ERROR_READ;
		} else rc = ERROR_NOT_NE;

		fclose(f);
	} else rc = ERROR_OPEN;
		
	return rc;
}

static bool in_section(PE_section_t *section, uint32_t rva, uint32_t *offset)
{
	if(rva >= section->VirtualAddress)
	{
		if(rva < (section->VirtualAddress+section->VirtualSize))
		{
			if(offset != NULL)
			{
				*offset = rva - section->VirtualAddress;
			}
			
			return true;
		}
	}
	return false;
}

typedef bool (*section_modif_callback_t)(PE_section_t *section, void *section_data, void *clb_data, uint32_t offset);

int pe_modify_section(const char *file, const char *name, int type, section_modif_callback_t clb, void *clb_data)
{
	EXE_header_t exe;
	PE_signature_t pe_sign;
	COFF_header_t coff;
	PE_header_t pe;
	PE_section_t section;
	char section_name[9] = {0};
	PE_image_directories_t image_dir;
	
	FILE *f;
	int rc = ERROR_NO_SECTION;
	long offset;
	
	memset(&image_dir, 0, sizeof(PE_image_directories_t));
	
	f = fopen(file, "r+b");
	if(f != NULL)
	{
		offset = EXE_offset(f, &exe);
		if(offset > 0)
		{
			if(read_move(f, offset))
			{
				if(read_header(f, sizeof(PE_signature_t), PE_SIGN, &pe_sign))
				{
					if(pe_sign.zero == 0)
					{
						if(read_block(f, sizeof(COFF_header_t), &coff))
						{
							if(coff.Machine == IMAGE_FILE_MACHINE_I386)
							{
								if(read_header(f, sizeof(PE_header_t), PE32, &pe))
								{
									size_t dir_size = sizeof(PE_image_directory_t) * pe.NumberOfRvaAndSizes;
									if(read_block(f, dir_size, &image_dir))
									{
										unsigned int i;
										/* skip extra space which not in PE_header_t */
										if(sizeof(PE_header_t)+dir_size < SIZE_OF_PE32)
										{
											fseek(f, SIZE_OF_PE32-(sizeof(PE_header_t)+dir_size), SEEK_CUR);
										}
										
										for(i = 0; i < coff.NumberOfSections; i++)
										{
											if(read_block(f, sizeof(PE_section_t), &section))
											{
												bool match = false;
												uint32_t data_offset = 0;
												memcpy(section_name, section.Name, 8);
												/*printf("section: %s %X %X\n", section_name, section.VirtualAddress, image_dir.ExportTable.VirtualAddress);*/
												if(name != NULL)
												{
													match = (stricmp(section_name, name) == 0);
												}
												else
												{
													switch(type)
													{
														case ID_EXPORT_TABLE:
															match = in_section(&section, image_dir.ExportTable.VirtualAddress, &data_offset);
															break;
														case ID_IMPORT_TABLE:
															match = in_section(&section, image_dir.ImportTable.VirtualAddress, &data_offset);
															break;
														case ID_RESOURCE_TABLE:
															match = in_section(&section, image_dir.ResourceTable.VirtualAddress, &data_offset);
															break;
														case ID_EXCEPTION_TABLE:
															match = in_section(&section, image_dir.ExceptionTable.VirtualAddress, &data_offset);
															break;
														case ID_CERTIFICATE_TABLE:
															match = in_section(&section, image_dir.CertificateTable.VirtualAddress, &data_offset);
															break;
														case ID_BASE_RELOCATION_TABLE:
															match = in_section(&section, image_dir.BaseRelocationTable.VirtualAddress, &data_offset);
															break;
													}
												}

												if(match)
												{
													void *ptr = malloc(section.VirtualSize);
													/*printf("match: %d\n", data_offset);*/
													
													if(ptr != NULL)
													{
														int block_read_size;
														memset(ptr, 0, section.VirtualSize);
														block_read_size = section.SizeOfRawData;
														if((uint32_t)block_read_size > section.VirtualSize)
														{
															block_read_size = section.VirtualSize;
														}
														
														read_block_begin(f, section.PointerToRawData, block_read_size, ptr);
														if(clb(&section, ptr, clb_data, data_offset))
														{
															writeback_block(f, block_read_size, ptr);
														}
														free(ptr);
														rc = OK;
														break;
													} else rc = ERROR_MALLOC;
												} /* section_name == name */
											} else rc = ERROR_READ;
										} /* for */
									} else rc = ERROR_READ;
								} else rc = ERROR_NOT_PE32;
							} else rc = ERROR_NOT_PE_I386;
						} else rc = ERROR_READ;
					} else rc = ERROR_NOT_PE;
				} else rc = ERROR_NOT_PE;
			} else rc = ERROR_READ;
		} else rc = ERROR_NOT_MZ;

		fclose(f);
	} else rc = ERROR_OPEN;
	
	return rc;
}

void *rva_to_ptr(uint32_t rva, PE_section_t *s, void *mem)
{
	uint32_t offset = rva - s->VirtualAddress;
	
	if(rva == 0) return NULL;
	if(offset >= s->VirtualSize) return NULL;
	
	return (((uint8_t*)mem) + offset);
}

uint32_t rva_to_off(uint32_t rva, PE_section_t *s)
{
	return rva - s->VirtualAddress;
}

uint32_t rva_from_ptr(void *ptr, PE_section_t *s, void *mem)
{
	return (((uint8_t*)ptr) - ((uint8_t*)mem)) + s->VirtualAddress;
}

size_t hnt_len(PE_hint_name_table_t *hnt)
{
	uint16_t *dst = (uint16_t *)hnt;
	size_t len = 2;
	do
	{
		dst++;
		len += 2;
	} while(
		((*dst) & 0x00FF) != 0 &&
		((*dst) & 0xFF00) != 0
	);
	
	return len;
}

uint8_t *found_space(size_t size, uint8_t *mem, size_t mem_size)
{
	uint8_t *ptr = mem;
	uint8_t *ptr_max = mem + (mem_size - size);
	
	while(ptr <= ptr_max)
	{
		int k;
		for(k = size - 1; k >= 0; k--)
		{
			if(ptr[k] != 0)
			{
				ptr += k+1;
				break;
			}
		}
		if(k < 0) return ptr;
	}
	return NULL;
}

#define MAX_REPLACE_DLLS 16
#define MAX_DLL_NAME 128
#define MAX_SYM_NAME 256

struct ht;
typedef struct args_dll_item
{
	const char *filename;
	char base[MAX_DLL_NAME];
	PE_idata_idt_t *idt;
	struct ht *ht;
	bool use_export_name;
	bool found;
} args_dll_item_t;

typedef struct args_dll
{
	int cnt;
	bool dofix;
	args_dll_item_t items[MAX_REPLACE_DLLS];
} args_dll_t;

static void filename2base(const char *fn, char *base)
{
	const char *pos_slash = strrchr(fn, '/');
	const char *pos_backslash = strrchr(fn, '\\');
	const char *pos_sep = NULL;
	if(pos_slash != NULL && pos_backslash != NULL)
	{
		if(pos_slash > pos_backslash)
			pos_sep = pos_slash;
		else
			pos_sep = pos_backslash;
	}
	else if(pos_slash != NULL)
		pos_sep = pos_slash;
	else if(pos_backslash != NULL)
		pos_sep = pos_backslash;
	
	if(pos_sep)
	{
		if(strlen(pos_sep+1) > 0)
		{
			sstrcpy(base, pos_sep+1, MAX_DLL_NAME);
			return;
		}
	}
	
	sstrcpy(base, fn, MAX_DLL_NAME);
}

/*
	https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
	PointerToRawData = file offset
	RVA - virtal address = offset to PointerToRawData
	
	[directory - 5 dwords:
		RVA import lookup table
		0
		0
		RVA dll name
		RVA import address table 
	]
*/

bool pe_relink_section(PE_section_t *section, void *section_data, void *clb_data, uint32_t data_offset)
{
	PE_idata_idt_t *idt = (PE_idata_idt_t*)(((uint8_t*)section_data)+data_offset);
	args_dll_t *args = clb_data;
	uint8_t *free_mem = malloc(section->VirtualSize);
	int dirs = 0;
	int i;
	uint8_t *new_pos;
	size_t new_size;
	bool rc = false;
	uint32_t min_rva = -1;

	if(free_mem != NULL)
	{
		memset(free_mem, 0, section->VirtualSize);
		do
		{
			if(idt->rva_import_lookup_table != 0)
			{
				char *name = rva_to_ptr(idt->rva_dllname, section, section_data);
				uint32_t *ilt = rva_to_ptr(idt->rva_import_lookup_table, section, section_data);
				size_t itl_len = 0;
				
				if(name != NULL)
				{
					for(i = 1; i < args->cnt; i++)
					{
						if(stricmp(name, args->items[i].base) == 0)
						{
							args->items[i].idt = idt;
							/*printf("found %s\n", rep->dlls[i]);*/
							if(idt->rva_dllname < min_rva)
							{
								min_rva = idt->rva_dllname;
							}
						}
					}
					
					while(*ilt != 0)
					{
						if(((*ilt) & ILT_IS_ORDINAL) == 0)
						{
							size_t hlen;
							PE_hint_name_table_t *hnt = rva_to_ptr(*ilt, section, section_data);
							if(hnt != NULL)
							{
								hlen = hnt_len(hnt);
								memset(rva_to_ptr(*ilt, section, free_mem), 0xFF, hlen);
							}
						}
						else
						{
							/* warn ordinal */
						}
						
						ilt++;
						itl_len++;
					}
					itl_len++;
					
					memset(
						rva_to_ptr(idt->rva_import_lookup_table, section, free_mem),
						0xFF, sizeof(PE_idata_idt_t));
					
					memset(
						rva_to_ptr(idt->rva_import_address_table, section, free_mem),
						0xFF, sizeof(PE_idata_idt_t));
						
					memset(
						rva_to_ptr(idt->rva_dllname, section, free_mem),
						0xFF, strlen(name)+1);
				} /* name != NULL */
			}
			memset(free_mem + data_offset + dirs*sizeof(PE_idata_idt_t), 0xFF, sizeof(uint32_t));
			idt++;
			dirs++;
		} while(idt->rva_import_lookup_table != 0);
		
		memset(free_mem, 0xFF, dirs * sizeof(PE_idata_idt_t));
		
		/* clear space with dll name as clean */
		for(i = 1; i < args->cnt; i++)
		{
			if(args->items[i].idt != NULL)
			{
				memset(
					rva_to_ptr(args->items[i].idt->rva_dllname, section, free_mem),
					0x00, strlen(args->items[i].base)+1);
				memset(
					rva_to_ptr(args->items[i].idt->rva_dllname, section, section_data),
					0x00, strlen(args->items[i].base)+1);
			}
			else
			{
				fprintf(stderr, "Warn: %s is not in import list\n", args->items[i].base);
			}
		}
		
		if(min_rva != (uint32_t)(-1))
		{
			new_size = strlen(args->items[0].base)+1;
			new_pos = found_space(new_size, free_mem+rva_to_off(min_rva, section), section->VirtualSize-rva_to_off(min_rva, section));
			if(new_pos == NULL)
			{
				new_pos = found_space(new_size, free_mem, section->VirtualSize);
			}
			
			if(new_pos != NULL)
			{
				uint32_t rva = rva_from_ptr(new_pos, section, free_mem);
				uint8_t *new_pos_sec = rva_to_ptr(rva, section, section_data);
				
				memcpy(new_pos_sec, args->items[0].base, new_size);
				rc = true;
				
				for(i = 1; i < args->cnt; i++)
				{
					if(args->items[i].idt != NULL)
					{
						printf("replaced %s (filename rva 0x%X) -> %s (filename rva 0x%X)\n",
							args->items[i].base, args->items[i].idt->rva_dllname,
							args->items[0].base, rva);
						args->items[i].idt->rva_dllname = rva;
					}
				}
			}
			else
			{
				fprintf(stderr, "Error: Can't find empty space of %d bytes in .idata\n", new_size);
			}
		}
		else
		{
			fprintf(stderr, "Warn: cannot find any library to replace\n");
		}
		
		free(free_mem);
	}
	
	if(!args->dofix) return false;
	
	return rc;
}

#define HT_PRIME 113

typedef struct ht_symbol
{
	char name[MAX_SYM_NAME];
	uint16_t ordinal;
	struct ht_symbol *next;
} ht_symbol_t;


typedef struct ht
{
	ht_symbol_t *items[HT_PRIME];
} ht_t;

/**
 * Based on djb2 function (http://www.cse.yorku.ca/~oz/hash.html).
 */
uint32_t ht_hash(const char *str)
{
	uint32_t hash = 5381;
	while(*str != '\0')
	{
		hash = ((hash << 5) + hash) + (*str); /* hash * 33 + c */
		str++;
	}
	
	return hash % HT_PRIME;
}

bool ht_insert(ht_t *ht, const char *name, uint32_t ordinal)
{
	ht_symbol_t **sym;
	ht_symbol_t *item;
	uint32_t hash = ht_hash(name);
	
	sym = &(ht->items[hash]);
	while(*sym != NULL)
	{
		if(stricmp(name, (*sym)->name) == 0)
		{
			printf("Warn: symbol %s exists - ordinal %u vs %u", name, (*sym)->ordinal, ordinal);
		}
		sym = &((*sym)->next);
	}
	item = malloc(sizeof(ht_symbol_t));
	if(item)
	{
		sstrcpy(item->name, name, MAX_SYM_NAME);
		item->ordinal = ordinal;
		item->next = NULL;
		*sym = item;
		return true;
	}
	return false;
}

bool ht_lookup(ht_t *ht, const char *name, uint32_t *ordinal)
{
	ht_symbol_t *sym = ht->items[ht_hash(name)];
	
	while(sym != NULL)
	{
		if(stricmp(name, sym->name) == 0)
		{
			if(ordinal != NULL)
			{
				*ordinal = sym->ordinal;
			}
			return true;
		}
		sym = sym->next;
	}
	return false;
}

ht_t *ht_create()
{
	ht_t *ht = malloc(sizeof(ht_t));
	
	if(ht)
	{
		memset(ht, 0, sizeof(ht_t));
	}
	
	return ht;
}

void ht_destroy(ht_t **ht)
{
	int i;
	
	if(*ht == NULL) return;
	
	for(i = 0; i < HT_PRIME; i++)
	{
		ht_symbol_t *sym = (*ht)->items[i];
		while(sym != NULL)
		{
			ht_symbol_t *garbage = sym;
			sym = sym->next;
			
			free(garbage);
		}
		(*ht)->items[i] = NULL;
	}
	
	free(*ht);
	
	*ht = NULL;
}

bool pe_hint_export(PE_section_t *section, void *section_data, void *clb_data, uint32_t data_offset)
{
	uint32_t y;
	args_dll_item_t *item = clb_data;
	PE_edata_edt_t *edt = (PE_edata_edt_t*)(((uint8_t*)section_data) + data_offset);
	const char *name = rva_to_ptr(edt->rva_dllname, section, section_data);
	uint32_t *name_table = rva_to_ptr(edt->rva_name_pointer, section, section_data);
	uint16_t *ordinal_table = rva_to_ptr(edt->rva_ordinal_table, section, section_data);
	
	if(name != NULL && item->use_export_name)
	{
		/*printf("export: %s\n", name);*/
		sstrcpy(item->base, name, MAX_DLL_NAME);
	}
	
	if(edt->number_of_name_pointers && name_table != NULL && ordinal_table != NULL)
	{
		for(y = 0; y < edt->number_of_name_pointers; y++)
		{
			const char *export_name = rva_to_ptr(name_table[y], section, section_data);
			if(export_name)
			{
				/*printf("%d\t%s\n", ordinal_table[y]+edt->ordinal_base, export_name);*/
				ht_insert(item->ht, export_name, ordinal_table[y]+edt->ordinal_base);
			}
		}
	}
	return false;
}

bool pe_hint_import(PE_section_t *section, void *section_data, void *clb_data, uint32_t data_offset)
{
	PE_idata_idt_t *idt = (PE_idata_idt_t*)(((uint8_t*)section_data) + data_offset);
	args_dll_t *args = clb_data;
	int updates = 0;
	
	while(idt->rva_import_lookup_table != 0)
	{
		char *name = rva_to_ptr(idt->rva_dllname, section, section_data);
		uint32_t *ilt = rva_to_ptr(idt->rva_import_lookup_table, section, section_data);

		if(name != NULL)
		{
			int i;
			for(i = 0; i < args->cnt; i++)
			{
				/*printf("check: %s == %s\n", name, args->items[i].base);*/
				if(stricmp(name, args->items[i].base) == 0)
				{
					while(*ilt != 0)
					{
						if(((*ilt) & ILT_IS_ORDINAL) == 0)
						{
							PE_hint_name_table_t *hnt = rva_to_ptr(*ilt, section, section_data);
							if(hnt != NULL)
							{
								uint32_t ord;
								if(ht_lookup(args->items[i].ht, hnt->name, &ord))
								{
									if(hnt->hint != ord)
									{
										/*printf("updating: %s - %d -> %d\n", hnt->name, hnt->hint, ord);*/
										updates++;
										hnt->hint = ord;
									}
								}
								else
								{
									fprintf(stderr, "Warn: export %s not found in %s\n", hnt->name, args->items[i].base);
								}
							}
						}
						ilt++;
					}
					args->items[i].found = true;
				}
			}
		}
		idt++;
	}
	
	if(updates > 0 && args->dofix)
	{
		return true;
	}
	
	return false;
}


#define MODE_UNSET 0
#define MODE_40 1
#define MODE_VXD32 2
#define MODE_SHARED 3
#define MODE_CHECKSUM 4
#define MODE_RELINK 5
#define MODE_HINT 6

#define CMP(_s) (stricmp(argv[i], _s) == 0)

int main(int argc, char *argv[])
{
	const char *filename = NULL;
	bool dofix = true;
	bool use_export_name = false;
	int mode = MODE_UNSET;
	int i;
	int rc = OK;
	error_msg_t *err_msg;
	static args_dll_t dlltable = {0};
	
	for(i = 1; i < argc; i++)
	{
		if(CMP("--dry-run"))
			dofix = false;
		else if(CMP("--use-export-name"))
			use_export_name = true;
		else if(CMP("-40"))
			mode = MODE_40;
		else if(CMP("-vxd32"))
			mode = MODE_VXD32;
		else if(CMP("-shared"))
			mode = MODE_SHARED;
		else if(CMP("-checksum"))
			mode = MODE_CHECKSUM;
		else if(CMP("-relink"))
			mode = MODE_RELINK;
		else if(CMP("-hint"))
			mode = MODE_HINT;
		else
		{
			if(filename == NULL)
			{
				filename = argv[i];
			}
			else
			{
				if(dlltable.cnt < MAX_REPLACE_DLLS)
				{
					dlltable.items[dlltable.cnt].filename = argv[i];
					filename2base(argv[i], dlltable.items[dlltable.cnt].base);
				}
				dlltable.cnt++;
			}
		}
	}
	
	if(mode != MODE_UNSET && filename == NULL)
	{
		rc = ERROR_NO_FILE;
	}
	else
	{
		switch(mode)
		{
			case MODE_40:
				rc = fix_wlink_drv(filename, 0x400, dofix);
				break;
			case MODE_VXD32:
				rc = fix_wlink_vxd(filename, dofix);
				break;
			case MODE_SHARED:
				rc = fix_pe_shared(filename, dofix);
				if(dofix && rc == OK)
				{
					rc = fix_pe_checksum(filename, true);
				}
				break;
			case MODE_CHECKSUM:
				rc = fix_pe_checksum(filename, dofix);
				break;
			case MODE_RELINK:
				if(dlltable.cnt >= 2)
				{
					dlltable.dofix = dofix;
					if(dlltable.cnt <= MAX_REPLACE_DLLS)
					{
						dlltable.dofix = dofix;
						rc = pe_modify_section(filename, NULL, ID_IMPORT_TABLE, pe_relink_section, &dlltable);
						if(rc == OK && dofix)
						{
							rc = fix_pe_checksum(filename, true);
						}
					} else rc = ERROR_TOO_MANY_DLL;
				} else rc = ERROR_NEED_2_AND_MORE_FILES;
				break;
			case MODE_HINT:
				if(dlltable.cnt >= 1)
				{
					int x, rc2;
					dlltable.dofix = dofix;
					for(x = 0; x < dlltable.cnt; x++)
					{
						dlltable.items[x].ht = ht_create();
						dlltable.items[x].use_export_name = use_export_name;
						
						if(dlltable.items[x].ht != NULL)
						{
							rc2 = pe_modify_section(dlltable.items[x].filename, NULL, ID_EXPORT_TABLE, pe_hint_export, &dlltable.items[x]);
							if(rc2 != OK)
							{
								fprintf(stderr, "Warn: cannot extract symbols from %s (rc=%d)\n", dlltable.items[x].filename, rc2);
							}
						}
					}
					rc = pe_modify_section(filename, NULL, ID_IMPORT_TABLE, pe_hint_import, &dlltable);
					
					for(x = 0; x < dlltable.cnt; x++)
					{
						ht_destroy(&(dlltable.items[x].ht));
						if(!dlltable.items[x].found)
						{
							fprintf(stderr, "Warn: DLL %s (%s) is not imported\n", dlltable.items[x].filename, dlltable.items[x].base);
						}
					}
					
					if(dofix) fix_pe_checksum(filename, true);
				} else rc = ERROR_NEED_1_AND_MORE_FILES;
				break;
			default:
				printf(help, argv[0]);
				break;
		}
	}
	
	/* fprintf(stderr, "rc=%d\n", rc); */
	
	if(rc == OK)
		return EXIT_SUCCESS;
	
	for(err_msg = &error_msg_table[0]; err_msg->txt != NULL; err_msg++)
	{
		if(rc == err_msg->code)
		{
			fprintf(stderr, "Error: %s\n", err_msg->txt);
			break;
		}
	}
	
	if(err_msg->txt == NULL)
	{
		fprintf(stderr, "Error: code %d\n", rc);
	}
	
	return EXIT_FAILURE;
}

