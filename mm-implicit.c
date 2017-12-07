/*
 * mm-implicit.c - an empty malloc package
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

/*macro*/
#define WSIZE 4	//Word크기 결정
#define DSIZE 8 //double Word크기 결정
#define CHUNKSIZE (1<<12)	//초기heap크기설정
#define OVERHEAD 8	//overhead사이즈

#define MAX(x,y) ((x)>(y)?(x):(y))	//x,y중 큰값
#define PACK(size,alloc) ((size)|(alloc))	//size,alloc값을 묶음

#define GET(p) (*(size_t*)(p))	//포인터의 위치에서word크기
#define PUT(p,val) (*(size_t*)(p)=(val))	//포인터위치에서 word크기의 val값을 쓴다

#define GET_SIZE(p) (GET(p)&~0x7)	//Header에서 block size읽음
#define GET_ALLOC(p) (GET(p)&0x1)	//block할당  여부

#define HDRP(bp) ((char*)(bp)-WSIZE)	//bp의 header주소
#define FTRP(bp) ((char*)(bp)+GET_SIZE(HDRP(bp)-DSIZE))	//dp의 footer주소 계산
#define NEXT_BLKP(bp) ((char*)(bp)+GET_SIZE((char*)(bp)-WSIZE))	//bp를 이용해서 다음block주소계산
#define PREV_BLKP(bp) ((char*)(bp)-GET_SIZE((char*)(bp)-DSIZE))	//bp를이용해서 이전 block주소계산
/*macro*/

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

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);

static char *heap_list=0;
static char *next_p;


/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
   
	if((heap_listp = mem_sbrk(4*WSIZE)) == NULL)	//초기heap
		return -1;

	PUT(heap_listp, 0);	//정렬을 위한 값
	PUT(heap_listp + WSIZE, PACK(OVERHEAD, 1));
	PUT(heap_listp + DSIZE, PACK(OVERHEAD, 1));
	PUT(heap_listp + WSIZE + DSIZE, PACK(0, 1));
	heap_listp += DSIZE;
	
	next_p = heap_list;

	if((extend_heap(CHUNKSIZE/WSIZE)) == NULL)
		return -1;

	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	size_t asize;
	size_t extendsize;
	char *bp;

	if(size == 0){	//size가 0인경우
	return NULL;
	}
	/*size<=8인 경우*/
	if(size<= DSIZE)
		asize = DSIZE + OVERHEAD;
	else
		asize = DSIZE*((size+(DSIZE)+(DSIZE-1))/DSZIE);
	//빈 공간 탐색
	if((bp = find_fit(asize))!=NULL){
		place(bp,asize);
		return bp;
	}
	//heap확장
	extendsize = MAX(asize,CHUNKSIZE);
	if((bp = extend_heap(extendsize/WSIZE))==NULL)
		return NULL;
	place(bp,asize);
	return bp;
}

/*coalesce() 인접한 free상태의 블록을 합쳐준다.*/
void *coalesce(void *bp){
}

/*palce() bp위치에 asize크기의 메모리를 위치시켜준다.*/
static void place(void *bp, size_t asize){

}

/*extend_heap() 요청받은 크기의 빈 블록을 만든다.*/
static void *extend_heap(size_t words)
{
	char *bp;
	size_t size;

	size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
	if((long)(bp=mem_sbrk(size))==-1)
		return NULL;

	PUT(HDRP(bp),PACK(size,0));
	PUT(FTRP(bp),PACK(size,0));
	PUT(HDRP(NEXT_BLKP(bp)),PACK(0,1));

	return coalesce(bp);
}

/*free block을 검색*/
static void *find_fit(size_t asize){

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
