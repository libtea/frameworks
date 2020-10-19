# README
========
For quick documentation, we recommend reading the root-level README.md. The individual module header files in include/ are also well documented. This documentation folder is designed to be generated with Sphinx for import to ReadTheDocs. To generate HTML documentation locally, run:

```
sudo apt-get install clang python3 python3-pip python3-clang
pip3 install -r requirements.txt
make html
```

If you encounter errors with the Python clang bindings, e.g. "libclang.so: cannot open shared object file", create a symbolic link for libclang.so from your specific clang version, e.g.:

```
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s libclang-10.so libclang.so
```
