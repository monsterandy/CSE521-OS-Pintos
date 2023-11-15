#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
bool is_valid_ptr (const void *ptr);

static void halt (void);
static void exit (int status);
static int write (int fd, const void *buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Check the validity of the syscall number and arguments. */
  if (!is_valid_ptr (f->esp) || !is_valid_ptr (f->esp + 4) || !is_valid_ptr (f->esp + 8) || !is_valid_ptr (f->esp + 12))
    exit (-1);

  // printf ("syscall esp: %p\n", f->esp);
  // printf ("syscall number: %d\n", *(int *)f->esp);
  // printf ("syscall arg1: %d\n", *(int *)(f->esp + 4));
  // printf ("syscall arg2: %p\n", *(char **)(f->esp + 8));
  // printf ("syscall arg3: %d\n", *(int *)(f->esp + 12));

  switch (*(int *)f->esp)
  {
    case SYS_HALT:
      halt ();
      break;
    case SYS_EXIT:
      exit (*(int *)(f->esp + 4));
      break;
    case SYS_EXEC:
      printf ("SYS_EXEC\n");
      break;
    case SYS_WAIT:
      printf ("SYS_WAIT\n");
      break;
    case SYS_CREATE:
      printf ("SYS_CREATE\n");
      break;
    case SYS_REMOVE:
      printf ("SYS_REMOVE\n");
      break;
    case SYS_OPEN:
      printf ("SYS_OPEN\n");
      break;
    case SYS_FILESIZE:
      printf ("SYS_FILESIZE\n");
      break;
    case SYS_READ:
      printf ("SYS_READ\n");
      break;
    case SYS_WRITE:
      f->eax = write (*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(int *)(f->esp + 12));
      break;
    case SYS_SEEK:
      printf ("SYS_SEEK\n");
      break;
    case SYS_TELL:
      printf ("SYS_TELL\n");
      break;
    case SYS_CLOSE:
      printf ("SYS_CLOSE\n");
      break;
    default:
      printf ("syscall number: %d\n", *(int *)f->esp);
      break;
  }

  // printf ("system call!\n");
  // thread_exit ();
}

bool
is_valid_ptr (const void *ptr)
{
  return ptr != NULL && is_user_vaddr (ptr) && pagedir_get_page (thread_current ()->pagedir, ptr) != NULL;
}

/* Terminates Pintos */
static void
halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel */
static void
exit (int status)
{
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}

/* Writes size bytes from buffer to the open file fd. 
  Returns the number of bytes actually written, 
  which may be less than size if some bytes could not be written. */
static int
write (int fd, const void *buffer, unsigned size)
{
  unsigned chk_size = size;
  void *chk_buffer = (void *) buffer;

  /* Check the validity of the buffer. */
  while (chk_size > 0)
  {
    if (!is_valid_ptr (chk_buffer))
      exit (-1);

    if (chk_size > PGSIZE)
    {
      chk_size -= PGSIZE;
      chk_buffer += PGSIZE;
    }
    else
      chk_size = 0;
  }

  /* Check the end of the buffer. */
  if (!is_valid_ptr (buffer + size - 1))
    exit (-1);

  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    return size;
  }
  else if (fd == STDIN_FILENO)
    return -1;
  else
    // TODO: write to file fd
    return -1;
}