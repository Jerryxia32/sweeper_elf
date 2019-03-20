#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<inttypes.h>
#include<libelf.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<assert.h>
#include<string.h>
#include<time.h>

size_t
get_filesize(const char* filename) {
  struct stat st;
  stat(filename, &st);
  return st.st_size;
}

static inline Elf64_Phdr*
elf_pheader(Elf64_Ehdr* hdr) {
  return (Elf64_Phdr*)((char*)hdr + hdr->e_phoff);
}

static inline Elf64_Phdr*
elf_segment(Elf64_Ehdr* hdr, int idx) {
  assert(idx < hdr->e_phnum);
  return &elf_pheader(hdr)[idx];
}

typedef struct _range {
  size_t low;
  size_t high;
} Range;

static size_t
get_timestamp () {
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_usec + (size_t)now.tv_sec * 1000000;
}

#define MMAP_SHADOW_FLAGS    (MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT|MAP_FIXED)
#define MMAP_SHADOW(addr, s)       mmap((void*)(addr), (s), PROT_READ|PROT_WRITE, MMAP_SHADOW_FLAGS, -1, 0)

static void sweep_page(size_t* thisPage);

int
main(int argc, char** argv) {
  if(argc != 2) {
    fprintf(stderr, "Error. Must have exactly one arg.\n");
    exit(-1);
  }

  const char* filename = argv[1];
  int fd = open(filename, O_RDWR);
  assert(fd >= 0);
  size_t filesize = get_filesize(filename);
  // p points to the start of the file map.
  void* p = mmap(NULL, filesize, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
  void* dummy = mmap((void*)0x80000, 0x1000, PROT_READ|PROT_WRITE, MMAP_SHADOW_FLAGS, -1, 0);
  assert(dummy != MAP_FAILED);
  printf("Created dummy mapping at 0x80000\n");
  Elf64_Ehdr* ehdr = (Elf64_Ehdr*)p;
  Elf64_Phdr* phdr = elf_pheader(ehdr);
  //Elf* theelf = elf_begin(fd, ELF_C_READ, NULL);
  //assert(theelf != NULL);
  //Elf64_Ehdr* ehdr = elf64_getehdr(theelf);
  //Elf64_Phdr* phdr = elf64_getphdr(theelf);
  printf("filename: %s, filesize: %zd\n", filename, filesize);

  // First, build small ranges.
  Range* ranges = NULL;
  size_t rangeCount = 0;
  for(int i=0; i<ehdr->e_phnum; i++) {
    Elf64_Phdr *seg = elf_segment(ehdr, i);
    if(seg->p_type==1 && seg->p_flags==6) { // LOAD segment with rw-
      //printf("SGMT: type:%x flags:%x offset:0x%lx vaddr:0x%lx filesz:0x%lx memsz:0x%lx align:0x%lx\n", seg->p_type, seg->p_flags, seg->p_offset, seg->p_vaddr, seg->p_filesz, seg->p_memsz, seg->p_align);
      if(seg->p_vaddr <= (size_t)0xffffffff) {
        rangeCount++;
        ranges = (Range*)realloc(ranges, sizeof(Range) * rangeCount);
        ranges[rangeCount-1].low = seg->p_vaddr;
        ranges[rangeCount-1].high = seg->p_vaddr + seg->p_memsz;
        void* ret = MMAP_SHADOW(seg->p_vaddr, seg->p_memsz);
        assert(ret != MAP_FAILED);
        memcpy(ret, (char*)p + seg->p_offset, seg->p_memsz);
      }
    }
  }

  for(size_t i=0; i<rangeCount; i++) {
    printf("low: 0x%lx, high: 0x%lx\n", ranges[i].low, ranges[i].high);
  }

  size_t pageCount = 0;
  size_t* pages = malloc(filesize/4096 * sizeof(size_t));
  for(size_t* ptr=p; (char*)ptr<(char*)p+filesize; ptr++) {
    size_t shiftAddr = ((*ptr)>>7); // FIXME: This is a hardcoded shift value.
    int found = 0;
    for(size_t i=0; i<rangeCount; i++) {
      if(shiftAddr>=ranges[i].low && shiftAddr<ranges[i].high) {
        if(pageCount==0 || pages[pageCount-1]!=((size_t)ptr>>12<<12)) {
          pageCount++;
          pages[pageCount-1] = ((size_t)ptr>>12<<12);
        }
        found = 1;
        break;
      }
    }
    if(!found)
      *ptr = 0;
  }
  printf("pageCount is: %zd\n", pageCount);

  assert(*(char*)dummy == 0);
  size_t t1 = get_timestamp();
  for(size_t i=0; i<pageCount; i++) {
    size_t* thisPage = (size_t*)pages[i];
    sweep_page(thisPage);
  }
  size_t t2 = get_timestamp();
  printf("usec passed %zd\n", t2-t1);

  printf("page density: %lf\n", (double)pageCount*4096/filesize);

  return 0;
}

// This is the kernel to sweep within one 4KiB page.
static inline void
sweep_page(size_t* thisPage) {
  for(size_t* ptr=thisPage; (char*)ptr<(char*)thisPage+4096; ptr+=4) {
    //if(*ptr != 0) {
    //  size_t bitIdx = ((*ptr)>>4) & 7;
    //  char* byte = (char*)((*ptr)>>7);
    //  if(*byte & (1<<bitIdx))
    //    *ptr = 0;
    //}
    size_t addr = *ptr;
    size_t addr2 = *(ptr+1);
    addr = (addr == 0)? 0x4000000:addr;
    addr2 = (addr2 == 0)? 0x4000000:addr2;
    size_t bitIdx = (addr>>4) & 7;
    size_t bitIdx2 = (addr2>>4) & 7;
    char* byte = (char*)(addr>>7);
    char* byte2 = (char*)(addr2>>7);
    if(*byte & (1<<bitIdx))
      *ptr = 0;
    if(*byte2 & (1<<bitIdx2))
      *(ptr+1) = 0;

    size_t addr3= *(ptr+2);
    size_t addr4 = *(ptr+3);
    addr3 = (addr3 == 0)? 0x4000000:addr3;
    addr4 = (addr4 == 0)? 0x4000000:addr4;
    size_t bitIdx3 = (addr3>>4) & 7;
    size_t bitIdx4 = (addr4>>4) & 7;
    char* byte3 = (char*)(addr3>>7);
    char* byte4 = (char*)(addr4>>7);
    if(*byte3 & (1<<bitIdx3))
      *(ptr+2) = 0;
    if(*byte4 & (1<<bitIdx4))
      *(ptr+3) = 0;
  }
}
