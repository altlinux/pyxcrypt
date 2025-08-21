"""
This file is part of pyxcrypt.

pyxcrypt is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pyxcrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with pyxcrypt.
If not, see <https://www.gnu.org/licenses/>.
"""


from . import pyxcrypt


def crypt_gensalt(prefix=None, count=0, rbytes=None, nrbytes=0):
    '''
    Compile a string for use as the setting argument to crypt

    :param prefix: selects the hashing method to use
    :type prefix: str, bytes-like-object or None
    :param count: controls the CPU time cost of the hash
    :type count: int
    :param rbytes: random bytes for use as a "salt"
    :type rbytes: str, bytes-like-object or None
    :param nrbytes: length of result
    :type nrbytes: int
    :return: salt
    :rtype: str
    '''
    hashes = {"yescrypt": "$y$",
              "gost-yescrypt": "$gy$",
              "gost_yescrypt": "$gy$",
              "sm3_yescrypt": "$sm3y$",
              "scrypt": "$7$",
              "bcrypt": "$2b$",
              "bcrypt_y": "$2y$",
              "bcrypt_a": "$2a$",
              "bcrypt_x": "$2x$",
              "sm3crypt": "$sm3$",
              "sha512crypt": "$6$",
              "sha256crypt": "$5$",
              "sha1crypt": "$sha1",
              "sunmd5": "$md5",
              "md5crypt": "$1$",
              "nt": "$3$",
              "bsdicrypt": "_",
              "descrypt": ""}
    return pyxcrypt._crypt_gensalt(prefix if prefix not in hashes else hashes[prefix], count, rbytes, nrbytes)


def crypt_gensalt_default(count=0, rbytes=None, nrbytes=0):
    '''
    Same as crypt_gensalt but with the default (prefered) hashing method

    :param count: controls the CPU time cost of the hash
    :type count: int
    :param rbytes: random bytes for use as a "salt"
    :type rbytes: str, bytes-like-object or None
    :param nrbytes: length of result
    :type nrbytes: int
    :return: salt
    :rtype: str
    '''
    return crypt_gensalt(None, count, rbytes, nrbytes)
