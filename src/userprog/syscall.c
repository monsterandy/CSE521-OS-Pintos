#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


static void syscall_handler (struct intr_frame *);
bool is_valid_ptr (const void *ptr);
struct fd_elem *get_fd_elem (int fd);

static void halt (void);
static void exit (int status);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
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
      f->eax = create (*(char **)(f->esp + 4), *(int *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      f->eax = remove (*(char **)(f->esp + 4));
      break;
    case SYS_OPEN:
      f->eax = open (*(char **)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      f->eax = filesize (*(int *)(f->esp + 4));
      break;
    case SYS_READ:
      f->eax = read (*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(int *)(f->esp + 12));
      break;
    case SYS_WRITE:
      f->eax = write (*(int *)(f->esp + 4), *(char **)(f->esp + 8), *(int *)(f->esp + 12));
      break;
    case SYS_SEEK:
      seek (*(int *)(f->esp + 4), *(int *)(f->esp + 8));
      break;
    case SYS_TELL:
      f->eax = tell (*(int *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      close (*(int *)(f->esp + 4));
      break;
    default:
      printf ("syscall unimplemented: %d\n", *(int *)f->esp);
      thread_exit ();
      break;
  }

  // printf ("system call!\n");
  // thread_exit ();
}

/* Returns true if the given pointer is a valid user pointer. */
bool
is_valid_ptr (const void *ptr)
{
  return ptr != NULL && is_user_vaddr (ptr) && pagedir_get_page (thread_current ()->pagedir, ptr) != NULL;
}

/* Returns the file descriptor element corresponding to the given fd. */
struct fd_elem *
get_fd_elem (int fd)
{
  struct list_elem *e;
  struct fd_elem *fd_elem = NULL;
  struct thread *t = thread_current ();

  for (e = list_begin (&t->fd_list); e != list_end (&t->fd_list); e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if (fd_elem->fd == fd)
      break;
  }
  if (e == list_end (&t->fd_list))
    fd_elem = NULL;
  return fd_elem;
}

/* Free the current process's file descriptors. */
void
close_all_files (struct thread *t)
{
  struct list_elem *e;
  struct fd_elem *fd_elem;

  for (e = list_begin (&t->fd_list); e != list_end (&t->fd_list); e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if (fd_elem->fd != STDIN_FILENO && fd_elem->fd != STDOUT_FILENO)
    {
      lock_acquire (&filesys_lock);
      file_close (fd_elem->file);
      list_remove (&fd_elem->elem);
      free (fd_elem);
      lock_release (&filesys_lock);
    }
  }
}

/* Terminates Pintos */
static void
halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. 
  If the process’s parent waits for it, this is the status that will be returned. 
  Conventionally, a status of 0 indicates success and nonzero values indicate errors. */
static void
exit (int status)
{
  struct thread *t = thread_current ();
  printf ("%s: exit(%d)\n", t->name, status);

  thread_exit ();
}

/* Creates a new file called file initially initial size bytes in size. 
  Returns true if successful, false otherwise. 
  Creating a new file does not open it: opening the new file is a separate operation 
  which would require a open system call. */
static bool
create (const char *file, unsigned initial_size)
{
  if (!is_valid_ptr (file))
    exit (-1);
  
  bool ret = false;
  lock_acquire (&filesys_lock);
  ret = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return ret;
}

/* Deletes the file called file. 
  Returns true if successful, false otherwise. 
  A file may be removed regardless of whether it is open or closed, 
  and removing an open file does not close it. */
static bool
remove (const char *file)
{
  if (!is_valid_ptr (file))
    exit (-1);
  
  bool ret = false;
  lock_acquire (&filesys_lock);
  ret = filesys_remove (file);
  lock_release (&filesys_lock);
  return ret;
}

/* Opens the file called file. 
  Returns a nonnegative integer handle called a “file descriptor” (fd), 
  or -1 if the file could not be opened. */
static int
open (const char *file)
{
  if (!is_valid_ptr (file))
    exit (-1);
  
  int ret = -1;
  struct file *f;
  struct fd_elem *fd_elem;

  lock_acquire (&filesys_lock);
  f = filesys_open (file);
  if (f != NULL)
  {
    fd_elem = calloc (1, sizeof (struct fd_elem));
    fd_elem->fd = thread_current ()->fd_count++;
    fd_elem->file = f;
    list_push_back (&thread_current ()->fd_list, &fd_elem->elem);
    ret = fd_elem->fd;
  }
  lock_release (&filesys_lock);
  return ret;
}

/* Returns the size, in bytes, of the file open as fd. */
int
filesize (int fd)
{
  int ret = -1;
  struct fd_elem *fd_elem = get_fd_elem (fd);
  if (fd_elem != NULL)
  {
    lock_acquire (&filesys_lock);
    ret = file_length (fd_elem->file);
    lock_release (&filesys_lock);
  }
  return ret;
}

/* Reads size bytes from the file open as fd into buffer. 
  Returns the number of bytes actually read (0 at end of file), 
  or -1 if the file could not be read (due to a condition other than end of file). */
static int
read (int fd, void *buffer, unsigned size)
{
  int ret = -1;
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

  lock_acquire (&filesys_lock);
  if (fd == STDIN_FILENO)
  {
    /* Read from the keyboard. */
    unsigned i;
    uint8_t *buf = (uint8_t *) buffer;
    for (i = 0; i < size; i++)
      buf[i] = input_getc ();
    ret = size;
  }
  else if (fd == STDOUT_FILENO)
    ret = -1;
  else
  {
    /* Read from the file. */
    struct fd_elem *fd_elem = get_fd_elem (fd);
    if (fd_elem != NULL)
      ret = file_read (fd_elem->file, buffer, size);
  }
  lock_release (&filesys_lock);
  return ret;
}

/* Writes size bytes from buffer to the open file fd. 
  Returns the number of bytes actually written, 
  which may be less than size if some bytes could not be written. */
static int
write (int fd, const void *buffer, unsigned size)
{
  int ret = -1;
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

  lock_acquire (&filesys_lock);
  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    ret = size;
  }
  else if (fd == STDIN_FILENO)
    ret = -1;
  else
  {
    /* Write to the file. */
    struct fd_elem *fd_elem = get_fd_elem (fd);
    if (fd_elem != NULL)
      ret = file_write (fd_elem->file, buffer, size);
  }
  lock_release (&filesys_lock);
  return ret;
}

/* Changes the next byte to be read or written in open file fd to position, 
  expressed in bytes from the beginning of the file. 
  (Thus, a position of 0 is the file’s start.) */
static void
seek (int fd, unsigned position)
{
  struct fd_elem *fd_elem = get_fd_elem (fd);
  if (fd_elem != NULL)
  {
    lock_acquire (&filesys_lock);
    file_seek (fd_elem->file, position);
    lock_release (&filesys_lock);
  }
}

/* Returns the position of the next byte to be read or written in open file fd, 
  expressed in bytes from the beginning of the file. */
static unsigned
tell (int fd)
{
  unsigned ret = -1;
  struct fd_elem *fd_elem = get_fd_elem (fd);
  if (fd_elem != NULL)
  {
    lock_acquire (&filesys_lock);
    ret = file_tell (fd_elem->file);
    lock_release (&filesys_lock);
  }
  return ret;
}

/* Closes file descriptor fd. 
  Exiting or terminating a process implicitly closes all its open file descriptors, 
  as if by calling this function for each one. */
static void
close (int fd)
{
  struct fd_elem *fd_elem = get_fd_elem (fd);
  if (fd_elem != NULL)
  {
    lock_acquire (&filesys_lock);
    file_close (fd_elem->file);
    list_remove (&fd_elem->elem);
    free (fd_elem);
    lock_release (&filesys_lock);
  }
}