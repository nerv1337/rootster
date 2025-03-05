#ifndef SHARED_H_ /* Include guard */
#define SHARED_H_

#include "linux/list.h"
#include "linux/types.h"

extern struct list_head filter_words;

struct filter_word {
  char *name;
  struct list_head list;
};

extern int hide_word(char *name);

#endif // SHARED_H_
