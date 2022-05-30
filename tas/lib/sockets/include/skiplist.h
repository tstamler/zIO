
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SKIPLIST_MAX_LEVEL 6

// address
typedef struct snode {
  uint64_t lookup; // lookup key
  uint64_t orig;   // the original buffer address
  uint64_t offset; // left fringe size
  uint64_t addr;   // buffer address
  uint64_t len;
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
  snode *header = (snode *)malloc(sizeof(struct snode));
  list->header = header;
  header->lookup = 0xffffffffffffffff;
  header->forward =
      (snode **)malloc(sizeof(snode *) * (SKIPLIST_MAX_LEVEL + 1));
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

static inline int skiplist_insert_with_addr(skiplist *list, uint64_t lookup,
                                            uint64_t orig, uint64_t addr,
                                            uint32_t len, uint64_t offset) {
  snode *update[SKIPLIST_MAX_LEVEL + 1];
  snode *x = list->header;
  int i, level;
  for (i = list->level; i >= 1; i--) {
    while (x->forward[i] && x->forward[i]->lookup < lookup)
      x = x->forward[i];
    update[i] = x;
  }

  /*
    if (x && x->addr > 0 && x->addr + x->offset + x->len >= addr) {
      return 1;
    }
    */

  x = x->forward[1];

  if (x && lookup == x->lookup) {
    x->orig = orig;
    x->len = len;
    x->offset = offset;
    x->addr = addr;
    return 0;
  } else {
    level = rand_level();
    if (level > list->level) {
      for (i = list->level + 1; i <= level; i++) {
        update[i] = list->header;
      }
      list->level = level;
    }

    x = (snode *)malloc(sizeof(snode));
    x->lookup = lookup;
    x->orig = orig;
    x->addr = addr;
    x->len = len;
    x->offset = offset;
    x->forward = (snode **)malloc(sizeof(snode *) * (level + 1));
    for (i = 1; i <= level; i++) {
      x->forward[i] = update[i]->forward[i];
      update[i]->forward[i] = x;
    }
  }
  return 0;
}

static inline int skiplist_insert(skiplist *list, uint64_t lookup,
                                  uint64_t orig, uint32_t len,
                                  uint64_t offset) {
  return skiplist_insert_with_addr(list, lookup, orig, lookup, len, offset);
}

static inline int skiplist_insert_entry(skiplist *list, snode *entry) {
  return skiplist_insert_with_addr(list, entry->lookup, entry->orig,
                                   entry->addr, entry->len, entry->offset);
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

static inline snode *skiplist_search_buffer_fallin(skiplist *list,
                                                   uint64_t addr) {
  snode *x = list->header;
  while (x && x->forward[1] != list->header) {
    if (x->forward[1]->addr + x->forward[1]->offset <= addr &&
        addr < x->forward[1]->addr + x->forward[1]->offset + x->forward[1]->len)
      return x->forward[1];
    x = x->forward[1];
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
    while (x->forward[i] && x->forward[i]->lookup < lookup)
      x = x->forward[i];
    update[i] = x;
  }

  x = x->forward[1];
  if (x && x->lookup == lookup) {
    for (i = 1; i <= list->level; i++) {
      if (update[i]->forward[i] != x)
        break;
      update[i]->forward[i] = x->forward[i];
    }
    skiplist_node_free(x);

    while (list->level > 1 &&
           list->header->forward[list->level] == list->header)
      list->level--;
    return 0;
  }
  return 1;
}

static inline snode *skiplist_front(skiplist *list) {
  snode *x = list->header;
  return x->forward[1];
}

static inline void skiplist_dump(skiplist *list) {
  snode *x = list->header;
  while (x && x->forward[1] != list->header) {
    printf("%p[%p, %p, %u, %u]->", x->forward[1]->lookup,
           (void *)x->forward[1]->orig, (void *)x->forward[1]->addr,
           x->forward[1]->len, x->forward[1]->offset);
    x = x->forward[1];
  }
  printf("NIL\n");
}

static inline snode *snode_get_next(skiplist *list, snode *node) {
  return node && node->forward[1] != list->header ? node->forward[1] : NULL;
}

static inline void snode_dump(const snode *node) {
  //   fprintf(stdout, "snode %p\n", node);
  fprintf(stderr, "\tlookup: %p\n", (void *)node->lookup);
  fprintf(stderr, "\torig: %p\n", (void *)node->orig);
  fprintf(stderr, "\taddr: %p\n", (void *)node->addr);
  fprintf(stderr, "\tlen: %lu\n", node->len);
  fprintf(stderr, "\toffset: %lu\n", node->offset);
  fprintf(stderr, "\tcore_buffer: %p-%p\n", node->addr + node->offset,
          node->addr + node->offset + node->len);
  fprintf(stderr, "\tcorresponding original: %p-%p\n",
          node->orig + node->offset, node->orig + node->offset + node->len);
}
