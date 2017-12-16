/*
 * mm-explicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201402420 
 * @name : 전형진
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/*macro*/
#define HDRSIZE 4
#define FTRSIZE 4
#define WSIZE 4	//Word크기 결정
#define DSIZE 8 //double Word크기 결정
#define CHUNKSIZE (1<<12)	//초기heap크기설정
#define OVERHEAD 8	//overhead사이즈

#define MAX(x,y) ((x)>(y)?(x):(y))	//x,y중 큰값
#define MIN(x,y) ((x)<(y)?(x):(y))
#define PACK(size,alloc) ((size)|(alloc))	//size,alloc값을 묶음

#define GET(p) (*(unsigned *)(p))	
#define PUT(p,val) (*(unsigned *)(p)=(unsigned)(val))
#define GET8(p) (*(unsigned long *)(p))
#define PUT8(p,val) (*(unsigned long *)(p)=(unsigned long)(val))
#define GET_SIZE(p) (GET(p)&~0x7)	//Header에서 block size읽음
#define GET_ALLOC(p) (GET(p)&0x1)	//block할당  여부

#define HDRP(bp) ((char *)(bp)-WSIZE)	//bp의 header주소
#define FTRP(bp) ((char *)(bp)+GET_SIZE(HDRP(bp))-DSIZE)	//dp의 footer주소 계산
#define NEXT_BLKP(bp) ((char *)(bp)+GET_SIZE(HDRP(bp)))	//bp를 이용해서 다음block주소계산
#define PREV_BLKP(bp) ((char *)(bp)-GET_SIZE((char *)(bp)-DSIZE))	//bp를이용해서 이전 block주소계산

#define NEXT_FREEP(bp) ((char *)(bp))
#define PREV_FREEP(bp) ((char *)(bp)+WSIZE)

#define NEXT_FREE_BLKP(bp) ((char *)GET8((char *)(bp)))
#define PREV_FREE_BLKP(bp) ((char *)GET8((char *)(bp)+WSIZE))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define SIZE_PTR(p) ((size_t*)(((char *)(p))-SIZE_T_SIZE))
/*macro*/

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

static void #extend_heap(size_t size, void *bp);
static void *find_fit(size_t asize, void *bp);
static void coalesce(void *ptr);
static void *place(void *ptr, size_t asize);
static void free_ptr_add(void *ptr);
static void free_ptr_delete(void *ptr);

void* free_bp=NULL;

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
 	void * heap_bottom = mem_heap_lo();
	free_bp = NULL;
	if((heap_bottom = mem_sbrk(2*WSIZE))==(void*)-1){
		return -1;
	}
	PUT(heap_bottom,Pack(0,1));
	PUT((char*)heap_bottom+WSIZE,PACK(0,1));
	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	if(size <= 0){
		return NULL;
	}
	unsigned int asize;
	void *bp = free_bp;

	if(size<=4*DSIZE){
		asize=4*DSIZE;
	}else{
		asize = ALIGN(size);
	}

	bp = find_fit(asize,bp);

	return bp;
}

static void *find_fit(size_t asize, void *bp){
	unsigned int tempsize = 0;
	while(bp != NULL){
		tempsize = GET_SIZE(HDRP(bp));
		if(tempsize>=asize){
			if(tempsize>=asize+32){
				return place(bp,asize);
			}
			free_ptr_delete(bp);
			PUT(HDRP(bp),PACK(tempsize,1));
			PUT(FTRP(bp),PACK(tempsize,1));
			return bp;
		}
		else{
			bp=NEXT_FREEP(bp);
		}
	}
	bp=extend_heap(asize,bp);
	return bp;
}

/*
 * free
 */
void free (void *ptr) {
    if(!ptr) return;
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
    return NULL;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    return NULL;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
