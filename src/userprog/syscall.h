#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);
void close_all_files (struct thread *t);
bool chk_ptr (const void *ptr);

struct lock filesys_lock;

/* File descriptor element. */
struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

#endif /* userprog/syscall.h */
