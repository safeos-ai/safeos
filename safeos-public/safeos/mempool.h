#ifndef SAFEOS_MEMPOOL_H
#define SAFEOS_MEMPOOL_H
// SafeOS physical memory pools. Include after types.h.
//   POOL_KERNEL  [0, 32 MB)        stacks, page tables, pipes
//   POOL_ROOT    [32 MB, 64 MB)    Owner-only memory: mapped in the Owner's page table alone
//   POOL_USER    [64 MB, PHYSTOP)  pages that user programs map

#define POOL_KERNEL  0
#define POOL_USER    1
#define POOL_ROOT    2
#define NPOOL        3

#define KERNPOOL_TOP  0x2000000   // where the kernel pool ends (32 MB)
#define ROOTPOOL_TOP  0x4000000   // where the Owner pool ends and the user pool starts (64 MB)
#define ROOTPOOL_SIZE (ROOTPOOL_TOP - KERNPOOL_TOP)

char* kalloc_user(void);                  // a page that will be mapped into user space
int   phys_in_pool(int which, uint pa);   // is physical address pa inside pool 'which'?
int   pool_info(int which, char *name, int namelen, int *nfree, int *ntotal);
int   root_alloc_page(uint *pa);          // a free Owner pool page; only the Owner can use it
void  root_free_page(uint pa);
int   map_rootpool(pde_t *pgdir);         // vm.c: map the Owner pool into one page directory
int   pgdir_maps(pde_t *pgdir, void *va); // vm.c: does this page directory map va?

int   map_ring1_page(pde_t *pgdir, uint va, char *page);   // vm.c: Ring 1 test pages (throwaway)
#define OWNER1_POOL_BASE 0x10000000   // where the Ring 1 Owner sees the Owner pool (virtual address)
int   map_ownerpool_low(pde_t *pgdir);    // vm.c: map the Owner pool at OWNER1_POOL_BASE
int   pgdir_maps_pool(pde_t *pgdir);      // vm.c: does this page directory map any Owner pool page?
int   root_page_is_allocated(uint pa);    // kalloc.c
#endif
