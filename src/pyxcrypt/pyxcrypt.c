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


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <crypt.h>


static PyObject * _crypt_gensalt(PyObject *self, PyObject *args)
{
    errno = 0;
    int nrbytes;
    unsigned long count;
    char *_hash = NULL;
    const char *prefix, *rbytes;
    Py_ssize_t *dumb_sz_1, *dumb_sz_2;

    if(PyTuple_Size(args) != 4)
    {
        PyErr_SetString(PyExc_TypeError, "Expected 4 arguments");
        return NULL;
    }
    if (PyArg_ParseTuple(args, "z#kz#i", &prefix, &dumb_sz_1, &count, &rbytes,
                &dumb_sz_2, &nrbytes) == -1)
    {
        PyErr_SetString(PyExc_TypeError, "Arguments parsing");
        return NULL;
    }

    if ((_hash = crypt_gensalt_ra(prefix, count, rbytes, nrbytes)) == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, strerror(errno));
        return NULL;
    }

    return Py_BuildValue("z", _hash);
}

static PyObject * _crypt(PyObject *self, PyObject *args)
{
    errno = 0;
    const char *phrase, *setting;
    char hash[CRYPT_GENSALT_OUTPUT_SIZE];
    struct crypt_data *data = NULL;
    Py_ssize_t *dumb_sz_1, *dumb_sz_2;

    if(PyTuple_Size(args) != 2)
    {
        PyErr_SetString(PyExc_TypeError, "Expected 2 arguments");
        return NULL;
    }
    if (PyArg_ParseTuple(args, "z#z#", &phrase, &dumb_sz_1, &setting,
                &dumb_sz_2) == -1)
    {
        PyErr_SetString(PyExc_TypeError, "Arguments parsing");
        return NULL;
    }
    if ((data = malloc(sizeof(*data))) == NULL)
    {
        PyErr_SetString(PyExc_MemoryError, strerror(errno));
        return NULL;
    }
    memset(data, 0, sizeof(*data));
    if (crypt_r(phrase, setting, data) == NULL || data->output[0] == '*')
    {
        PyErr_SetString(PyExc_RuntimeError, strerror(errno));
        free(data);
        return NULL;
    }

    memcpy(hash, data->output, CRYPT_GENSALT_OUTPUT_SIZE);
    free(data);

    return Py_BuildValue("z", hash);
}

static PyObject * _crypt_checksalt(PyObject *self, PyObject *args)
{
    errno = 0;
    const char *setting;
    Py_ssize_t *dumb_sz_1;

    if(PyTuple_Size(args) != 1)
    {
        PyErr_SetString(PyExc_TypeError, "Expected 2 arguments");
        return NULL;
    }
    if (PyArg_ParseTuple(args, "z#", &setting, &dumb_sz_1) == -1)
    {
        PyErr_SetString(PyExc_TypeError, "Arguments parsing");
        return NULL;
    }

    return Py_BuildValue("i", crypt_checksalt(setting));
}

static PyMethodDef PyXcryptMethods[] = {
    {"_crypt_gensalt", _crypt_gensalt, METH_VARARGS,
     "compile a string for use as the setting argument to crypt"},
    {"_crypt", _crypt, METH_VARARGS,
     "irreversibly \"hash\" phrase using a cryptographic \"hashing method\""},
    {"_crypt_checksalt", _crypt_checksalt, METH_VARARGS,
     "checks the setting string against the system configuration and reports "
     "whether the hashing method and parameters it specifies are acceptable"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pyxcrypt = {
    PyModuleDef_HEAD_INIT,
    "pyxcrypt",
    NULL,
    -1,
    PyXcryptMethods
};

PyMODINIT_FUNC
PyInit_pyxcrypt(void){
    return PyModule_Create(&pyxcrypt);
}
