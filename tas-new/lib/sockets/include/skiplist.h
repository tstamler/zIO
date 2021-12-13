
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
 
#define SKIPLIST_MAX_LEVEL 6
 
typedef struct snode {
    uint64_t lookup;
    uint64_t orig;
    uint64_t offset;
    uint32_t len;
    uint8_t free;
    struct snode **forward;
} snode;
 
typedef struct skiplist {
    int level;
    int size;
    struct snode *header;
} skiplist;
 
static inline skiplist *skiplist_init(skiplist *list) {
    int i;
    snode *header = (snode *) malloc(sizeof(struct snode));
    list->header = header;
    header->lookup = 0xffffffffffffffff;
    header->forward = (snode **) malloc(
            sizeof(snode*) * (SKIPLIST_MAX_LEVEL + 1));
    for (i = 0; i <= SKIPLIST_MAX_LEVEL; i++) {
        header->forward[i] = list->header;
    }
 
    list->level = 1;
    list->size = 0;
 
    return list;
}
 
static inline int rand_level() {
    int level = 1;
    while (rand() < RAND_MAX / 2 && level < SKIPLIST_MAX_LEVEL)
        level++;
    return level;
}
 
static inline int skiplist_insert(skiplist *list, uint64_t lookup, uint64_t orig, uint32_t len, uint64_t offset) {
    snode *update[SKIPLIST_MAX_LEVEL + 1];
    snode *x = list->header;
    int i, level;
    for (i = list->level; i >= 1; i--) {
        while (x->forward[i]->lookup < lookup)
            x = x->forward[i];
        update[i] = x;
    }
    x = x->forward[1];
 
    if (lookup == x->lookup) {
        x->orig = orig;
	x->len = len;
	x->offset = offset;
        return 0;
    } else {
        level = rand_level();
        if (level > list->level) {
            for (i = list->level + 1; i <= level; i++) {
                update[i] = list->header;
            }
            list->level = level;
        }
 
        x = (snode *) malloc(sizeof(snode));
        x->lookup = lookup;
        x->orig = orig;
	x->len = len;
	x->offset = offset;
        x->forward = (snode **) malloc(sizeof(snode*) * (level + 1));
        for (i = 1; i <= level; i++) {
            x->forward[i] = update[i]->forward[i];
            update[i]->forward[i] = x;
        }
    }
    return 0;
}
 
static inline snode *skiplist_search(skiplist *list, uint64_t lookup) {
    snode *x = list->header;
    int i;
    for (i = list->level; i >= 1; i--) {
        while (x->forward[i]->lookup < lookup)
            x = x->forward[i];
    }
    if (x->forward[1]->lookup == lookup) {
        return x->forward[1];
    } else {
        return NULL;
    }
    return NULL;
}
 
static inline void skiplist_node_free(snode *x) {
    if (x) {
        free(x->forward);
        free(x);
    }
}
 
static inline int skiplist_delete(skiplist *list, uint64_t lookup) {
    int i;
    snode *update[SKIPLIST_MAX_LEVEL + 1];
    snode *x = list->header;
    for (i = list->level; i >= 1; i--) {
        while (x->forward[i]->lookup < lookup)
            x = x->forward[i];
        update[i] = x;
    }
 
    x = x->forward[1];
    if (x->lookup == lookup) {
        for (i = 1; i <= list->level; i++) {
            if (update[i]->forward[i] != x)
                break;
            update[i]->forward[i] = x->forward[i];
        }
        skiplist_node_free(x);
 
        while (list->level > 1 && list->header->forward[list->level]
                == list->header)
            list->level--;
        return 0;
    }
    return 1;
}
 
static inline void skiplist_dump(skiplist *list) {
    snode *x = list->header;
    while (x && x->forward[1] != list->header) {
        printf("%lx[%lx, %u]->", x->forward[1]->lookup, x->forward[1]->orig, x->forward[1]->len);
        x = x->forward[1];
    }
    printf("NIL\n");
}

