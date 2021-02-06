#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "../tawny.h"

#include "Python.h"
#include "structmember.h"


typedef struct {
	PyObject_HEAD
	PyObject *plaintext;
	PyObject *key;
	PyObject *iv;
	PyObject *ciphertext;

	unsigned char c_key[TAWNY_KEY_LENGTH_BYTES+1];
	unsigned char c_iv[TAWNY_IV_LENGTH_BYTES+1];
	unsigned char *c_plaintext;
	unsigned char *c_ciphertext;
} TawnyCipher;

static void TawnyCipher_dealloc(TawnyCipher *self) {
	Py_XDECREF(self->plaintext);
	Py_XDECREF(self->iv);
	Py_XDECREF(self->key);
	Py_XDECREF(self->ciphertext);

	memset(self->c_iv, '\0', sizeof(self->c_iv));
	memset(self->c_key, '\0', sizeof(self->c_key));

//	Py_TYPE(self)->tp_free((PyObject)*self);
}

static PyObject *TawnyCipher_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	TawnyCipher *self;
	self = (TawnyCipher*)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->plaintext = PyUnicode_FromString("");

		if (self->plaintext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		self->key = PyUnicode_FromString("");

		if (self->key == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		self->iv = PyUnicode_FromString("");

		if (self->iv == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		self->ciphertext = PyUnicode_FromString("");

		if (self->ciphertext == NULL) {
			Py_DECREF(self);

			return NULL;
		}

		memset(self->c_iv, '\0', sizeof(self->c_iv));
		memset(self->c_key, '\0', sizeof(self->c_iv));

	}

	return (PyObject*)self;
}

static int TawnyCipher_init(TawnyCipher *self, PyObject *args, PyObject *kwds) {
	if (!PyArg_ParseTuple(args, "O", &self->key)) {
		return -1;
	}

	PyObject *key_repr = PyObject_Str(self->key);

	if (key_repr == NULL) {
		return -1;
	}

	PyObject *key_str = PyUnicode_AsEncodedString(key_repr, "ascii", "~E~");

	const char *key = PyBytes_AsString(key_str);

	if (strlen(key) != TAWNY_KEY_LENGTH_BYTES) {
		PyErr_SetString(PyExc_AttributeError, "The key must be 32 bytes in length");

		return -1;
	}

	memcpy(self->c_key, key, strlen(key));

	return 0;
}

static PyObject *TawnyCipher_Encrypt(TawnyCipher *self, PyObject *Py_UNUSED(ignored)) {
	if (self->plaintext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "The plaintext has not been set");

		return NULL;
	}

	PyObject *iv_repr = PyObject_Str(self->iv);

	if (iv_repr == NULL) {
		if (RAND_bytes(self->c_iv, TAWNY_IV_LENGTH_BYTES) < 0) {
			PyErr_SetString(PyExc_RuntimeError, "Failed generating the IV");

			return NULL;
		}

		self->iv = PyUnicode_FromString((char*)self->c_iv);
	} else {
		PyObject *iv_str = PyUnicode_AsEncodedString(iv_repr, "ascii", "~E~");
		char *iv = PyBytes_AsString(iv_str);

		memcpy(self->c_iv, (unsigned char*)iv, strlen(iv));

		if (strlen(iv) > 0 && strlen(iv) != TAWNY_IV_LENGTH_BYTES) {
			PyErr_SetString(PyExc_AttributeError, "The IV must be 32 bytes in length");

			return NULL;
		}
	}

	PyObject *pt_repr = PyObject_Str(self->plaintext);

	if (pt_repr == NULL) {
		self->plaintext = PyUnicode_FromString("");
	}

	PyObject *pt_str = PyUnicode_AsEncodedString(pt_repr, "ascii", "~E~");

	const char *unpadded_plaintext = PyBytes_AsString(pt_str);
	const char *padded_plaintext = (const char*)pkcs7pad((unsigned char*)unpadded_plaintext, strlen(unpadded_plaintext), TAWNY_BLOCK_SIZE_BYTES);

	Tawny_CTX ctx;
	Tawny_Init(&ctx);

	if (!Tawny_Update(TAWNY_UPDATE_PLAINTEXT, &ctx, NULL, NULL, (unsigned char*)padded_plaintext, NULL, strlen(padded_plaintext), 0)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context plaintext");

		return NULL;
	}

	if (!Tawny_Update(TAWNY_UPDATE_IV, &ctx, self->c_iv, NULL, NULL, NULL, 0, 0)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context IV");

		return NULL;
	}

	if (!Tawny_Update(TAWNY_UPDATE_KEY, &ctx, NULL, self->c_key, NULL, NULL, 0, 0)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context key");

		return NULL;
	}

	size_t bytes_encrypted = Tawny_Encrypt(&ctx);

	if (bytes_encrypted < 1) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to encrypt, check values are stable");

		return NULL;
	}

	PyObject *ciphertext_key = PyUnicode_FromString("ciphertext");
	PyObject *iv_key = PyUnicode_FromString("iv");
	PyObject *key_key = PyUnicode_FromString("key");

	PyObject *ciphertext_item = PyUnicode_FromString((char*)ctx.ciphertext);

	self->ciphertext = ciphertext_item;

	PyObject *iv_item = PyUnicode_FromString((char*)self->c_iv);
	PyObject *key_item = PyUnicode_FromString((char*)self->c_key);

	PyObject *ret_dict = PyDict_New();

	PyDict_SetItem(ret_dict, ciphertext_key, ciphertext_item);
	PyDict_SetItem(ret_dict, iv_key, iv_item);
	PyDict_SetItem(ret_dict, key_key, key_item);

	Py_XDECREF(ciphertext_key);
	Py_XDECREF(ciphertext_item);
	Py_XDECREF(iv_key);
	Py_XDECREF(iv_item);
	Py_XDECREF(key_key);
	Py_XDECREF(key_item);

	return ret_dict;
}

static PyObject *TawnyCipher_Decrypt(TawnyCipher *self, PyObject *Py_UNUSED(ignored)) {
	if (self->ciphertext == NULL) {
		PyErr_SetString(PyExc_AttributeError, "The ciphertext has not been set");

		return NULL;
	}

	if (self->iv == NULL) {
		PyErr_SetString(PyExc_AttributeError, "The IV has not been set");

		return NULL;
	}

	PyObject *iv_repr = PyObject_Str(self->iv);
	PyObject *iv_str = PyUnicode_AsEncodedString(iv_repr, "ascii", "~E~");
	char *iv = PyBytes_AsString(iv_str);

	if (strlen(iv) > 0 && strlen(iv) != TAWNY_IV_LENGTH_BYTES) {
		PyErr_SetString(PyExc_AttributeError, "The IV must be 32 bytes in length");

		return NULL;
	}

	memcpy(self->c_iv, iv, strlen(iv));

	PyObject *ct_repr = PyObject_Str(self->ciphertext);
	PyObject *ct_str = PyUnicode_AsEncodedString(ct_repr, "ascii", "~E~");

	const char *ciphertext = PyBytes_AsString(ct_str);

	Tawny_CTX ctx;
	Tawny_Init(&ctx);

	if (!Tawny_Update(TAWNY_UPDATE_CIPHERTEXT, &ctx, NULL, NULL, NULL, (unsigned char*)ciphertext, 0, strlen(ciphertext))) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context ciphertext");

		return NULL;
	}

	if (!Tawny_Update(TAWNY_UPDATE_IV, &ctx, self->c_iv, NULL, NULL, NULL, 0, 0)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context IV");

		return NULL;
	}

	if (!Tawny_Update(TAWNY_UPDATE_KEY, &ctx, NULL, self->c_key, NULL, NULL, 0, 0)) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to update the context key");

		return NULL;
	}

	size_t bytes_decrypted = Tawny_Decrypt(&ctx);

	if (bytes_decrypted < 1) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to decrypt, check values are stable");

		return NULL;
	}

	PyObject *plaintext_key = PyUnicode_FromString("plaintext");
	PyObject *iv_key = PyUnicode_FromString("iv");
	PyObject *key_key = PyUnicode_FromString("key");

	PyObject *plaintext_item = PyUnicode_FromString((char*)ctx.plaintext);

	self->plaintext = plaintext_item;

	PyObject *iv_item = PyUnicode_FromString((char*)self->c_iv);
	PyObject *key_item = PyUnicode_FromString((char*)self->c_key);

	PyObject *ret_dict = PyDict_New();

	PyDict_SetItem(ret_dict, plaintext_key, plaintext_item);
	PyDict_SetItem(ret_dict, iv_key, iv_item);
	PyDict_SetItem(ret_dict, key_key, key_item);

	Py_XDECREF(plaintext_key);
	Py_XDECREF(plaintext_item);
	Py_XDECREF(iv_key);
	Py_XDECREF(iv_item);
	Py_XDECREF(key_key);
	Py_XDECREF(key_item);

	return ret_dict;
}

static PyMemberDef TawnyCipher_members[] = {
	{"plaintext", T_OBJECT_EX, offsetof(TawnyCipher, plaintext), 0, "Tawny Cipher plaintext value"},
	{"iv", T_OBJECT, offsetof(TawnyCipher, iv), 0, "Tawny Cipher initialization vector"},
	{"key", T_OBJECT, offsetof(TawnyCipher, key), 0, "Tawny Cipher key"},
	{"ciphertext", T_OBJECT_EX, offsetof(TawnyCipher, ciphertext), 0, "Tawny Cipher plaintext value"},
	{NULL}
};

static PyMethodDef TawnyCipher_methods[] = {
	{"Encrypt", (PyCFunction)TawnyCipher_Encrypt, METH_NOARGS, "Encrypt the current Tawny context (returns dictionary of updated context)"},
	{"Decrypt", (PyCFunction)TawnyCipher_Decrypt, METH_NOARGS, "Decrypt the current Tawny context (returns dictionary of updated context)"},
	{NULL}
};

static PyTypeObject TawnyCipherType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "tawny.context",
	.tp_basicsize = sizeof(TawnyCipher),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_new = TawnyCipher_new,
	.tp_init = (initproc)TawnyCipher_init,
	.tp_dealloc = (destructor)TawnyCipher_dealloc,
	.tp_members = TawnyCipher_members,
	.tp_methods = TawnyCipher_methods
};

static PyModuleDef TawnyCipherModule = {
	PyModuleDef_HEAD_INIT,
	.m_name = "tawny",
	.m_doc = "A python3 wrapper for the tawny cipher library",
	.m_size = 01,
};

PyMODINIT_FUNC PyInit_tawny(void) {
	PyObject *m;

	if (PyType_Ready(&TawnyCipherType) < 0) {
		return NULL;
	}

	m = PyModule_Create(&TawnyCipherModule);

	Py_INCREF(&TawnyCipherType);

	if (PyModule_AddObject(m, "context", (PyObject*)&TawnyCipherType) < 0) {
		Py_DECREF(&TawnyCipherType);
		Py_DECREF(m);

		return NULL;
	}

	return m;
}
