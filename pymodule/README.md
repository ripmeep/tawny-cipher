# Setup python3 module

```
python3 setup.py build
python3 setup.py install
```

# Example encryption & decryption

```py

import tawny

key = "my_super_secret_example_key_1234"
iv = "23902390239023902390239023902390"


print("\n======================= ENCRYPTION =======================")

t = tawny.context(key)
t.plaintext = "hello world!"
t.iv = iv

encrypted = t.Encrypt() # {'ciphertext': '%\x1e\x11\x10\x18\x0f\x05\x1d\x01UIQ(\x08\x07 uf\x0fizAym*\t\x05\x0f,h@H', 'iv': '1234567890123456789001234567890abcdef', 'key': 'my_super_secret_example_key_1234'}

print("""
Key:        {}
Ciphertext: {}
""".format(t.iv, t.ciphertext.encode('utf-8').hex()))



print("======================= DECRYPTION =======================")

td = tawny.context(key) # New context
td.ciphertext = t.ciphertext
td.iv = iv

decrypted = td.Decrypt() # {'plaintext': 'hello world!', 'iv': '23902390239023902390239023902390', 'key': 'my_super_secret_example_key_1234'}

print("""
Key:       {}
Plaintext: {}
""".format(t.iv, t.plaintext))
```
