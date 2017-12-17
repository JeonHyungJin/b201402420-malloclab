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

static void *extend_heap(size_t size, void *bp);
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
 	//초기 empty heap
	void * heap_bottom = mem_heap_lo();
	free_bp = NULL;	//초기화
	if((heap_bottom = mem_sbrk(2*WSIZE))==(void*)-1){
		//초기 heap크기 확장
		return -1;
	}
	//할당
	PUT(heap_bottom,Pack(0,1));
	PUT((char*)heap_bottom+WSIZE,PACK(0,1));
	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	if(size <= 0){	//할당사이즈 0이하
		return NULL;
	}
	unsigned int asize;
	void *bp = free_bp;

	if(size<=4*DSIZE){	//할당사이즈가 32이하
		asize=4*DSIZE;
	}else{
		asize = ALIGN(size);
	}

	bp = find_fit(asize,bp);

	return bp;
}

static void *find_fit(size_t asize, void *bp){
	unsigned int tempsize = 0;//bp의 size를 저장할 변수
	while(bp != NULL){	//처음부터 검색
		tempsize = GET_SIZE(HDRP(bp));
		if(tempsize>=asize){
			if(tempsize>=asize+32){
				return place(bp,asize);	//block을 나누어 할당
			}
			free_ptr_delete(bp);	//free block ptr제거
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

static void *extend_heap(size_t size, void *bp){
	bp = mem_sbrk(size+2*WSIZE);
	//heap 확장
	if((long)bp == -1){	//실패시
		return NULL;
	}
	//메모리 할당
	PUT(HDRP(bp),PACK(size, 1));
	PUT(FTRP(bp),PACK(size, 1));
	PUT(FTRP(bp)+WSIZE,PACK(0,1));
	return bp;
}


/*
 * free
 */
void free (void *ptr) {
    if(!ptr) return;

	if(GET_ALLOC(HDRP(ptr))==0) return;

	size_t size = GET_SIZE(HDRP(ptr));

	PUT(HDRP(ptr),PACK(size,0));
	PUT(FTRP(ptr),PACK(size,0));

	if(free_bp != NULL){
		coalesce(ptr);
	}else{
		free_ptr_add(ptr);
	}
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
    size_t oldsize;
	void *newptr;

	if(size==0){
		mm_free(oldptr);
		return 0;
	}
	if(oldptr==NULL){
		return mm_malloc(size);
	}
	newptr = mm_malloc(size);

	if(!newptr){
		return 0;
	}
	oldsize = GET_SIZE(HDRP(oldptr));
	if(size < oldsize)	oldsize = size;
	memcpy(newptr,oldptr,oldsize);

	mm_free(oldptr);

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    size_t bytes = nmemb * size;
	void *newptr;
	newptr = malloc(bytes);
	memset(newptr, 0 ,bytes);
	return newptr;
}

static void coalesce(void *ptr){
	size_t next_alloc = GET_ALLOC((char *)(FTRP(ptr))+WSIZE);
	//다음 block 할당 여부
	size_t prev_alloc = GET_ALLOC((char *)(ptr)-DSIZE);
	//이전 block 할당 여부
	size_t size = GET_SIZE(HDRP(ptr));
	//ptr block 크기

	if(prev_alloc && next_alloc){
		free_ptr_add(ptr);
	}
	else if(prev_alloc && !next_alloc){
		size+= GET_SIZE(HDRP(NEXT_BLKP(ptr)))+2*WSIZE;
		free_ptr_delete(NEXT_BLKP(ptr));
		PUT(HDRP(ptr), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
		free_ptr_add(ptr);
	}
	else if(!prev_alloc && next_alloc){
		ptr = PREV_BLKP(ptr);
		size += GET_SIZE(HDRP(ptr))+2*WSIZE;
		PUT(HDRP(ptr), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
	}
	else{
		void * prev = PREV_BLKP(ptr);
		void * next = NEXT_BLKP(ptr);
		size += GET_SIZE(HDRP(prev))+GET_SIZE(HDRP(next))+4*WSIZE;
		PUT(HDRP(prev), PACK(size, 0));
		PUT(FTRP(prev), PACK(size, 0));
		free_ptr_delete(next);
	}
}

static void* place(void *ptr, size_t asize){
	int csize = GET_SIZE(HDRP(ptr))-asize-2*WSIZE;

	PUT(HDRP(ptr),PACK(csize,0));
	PUT(FTRP(ptr),PACK(csize,0));

	void *p=NEXT_BLKP(ptr);

	PUT(HDRP(p),PACK(asize,1));
	PUT(FTRP(p),PACK(asize,1));
	return p;
}

static void free_ptr_add(void *ptr){
	void *head = free_bp;
	NEXT_FREE_BLKP(ptr,head);
	PREV_FREE_BLKP(ptr,NULL);
	if(head!=NULL)
		PREV_FREE_BLKP(head,ptr);
	free_bp = ptr;
}

static void free_ptr_delete(void *ptr){

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
