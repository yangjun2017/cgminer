/*
 * Copyright 2016 Mikeqin <Fengling.Qin@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#ifndef LIBSSPLUS_H
#define LIBSSPLUS_H

typedef uint32_t ssp_pair[2];

int  ssp_hasher_init(void);
void ssp_hasher_update_stratum(struct pool *pool, bool clean);
void ssp_hasher_test(void);

void ssp_sorter_init(void);
int  ssp_sorter_get_pair(ssp_pair pair);

#endif /* LIBSSPLUS_H */
