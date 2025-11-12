/*
 * This file is part of pyxcrypt.
 *
 * pyxcrypt is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * pyxcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pyxcrypt.
 * If not, see <https://www.gnu.org/licenses/>.
 */

#include <pyxcrypt-config.h>

#if defined PYXCRYPT_USE_MEMERASE_IMPL

#include <string.h>

/* Keep this in a seperate translation-unit,
   so the compiler will not start to optimize this away.  */
NO_INLINE void pyxcrypt_memerase(void *p, size_t l)
{
  p = memset (p, 0, l);
  asm volatile ("" : : "g" (p) : "memory");
}
#endif /* PYXCRYPT_USE_MEMERASE_IMPL */
