#ifndef BITMAP_H
#define BITMAP_H

#include "signature.h"
#include "parallel.h"

idx_type bitmap_get_free_index();
void bitmap_ret_free_index(idx_type);
void bitmap_init(int);

#endif
