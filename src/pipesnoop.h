#ifndef PIPESNOOP_H
#define PIPESNOOP_H

#define MAX_BUF_SIZE 500

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum pipesnoop_action {
    READ = 0,
    WRITE,
};

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    enum pipesnoop_action action;
    int real_size;
    char buff[MAX_BUF_SIZE];
};

#endif  // PIPESNOOP_H