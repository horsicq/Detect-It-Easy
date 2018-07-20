/*
  dieclu.c - "Universal" console version of Detect It Easy using the library.

  Jason Hood, 2, 11, 15 & 26 May, 2014.

  v1.00, 5 June, 2014:
  + help screen;
  + -a option to include all files (non-existent, unreadable, directories).

  v1.01, 3 August, 2014:
  + -d option and DIE_DB environment variable to select database;
  * --version includes DIE's version.

  v1.02, 16 September, 2014:
  + -E option to show entropy.

  v1.03, 19 September, 2014:
  * resize buffer to fit contents;
  * flush output to work better with a pipe;
  + -n option to prevent single line file name alignment;
  * now that it does everything diec does (apart from signature counts), "lite"
     no longer applies - call it "library" instead.

*/

#define PVERS "1.03"
#define PDATE "19 September, 2014"

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "diedll.h"


// Determine the status of a file:
//   0 - normal
//   1 - directory
//   2 - unreadable
//   3 - doesn't exist
int status( const char* name )
{
#ifdef _WIN32
  DWORD a;

  a = GetFileAttributes( name );
  if (a == -1)
    return (GetLastError() == ERROR_ACCESS_DENIED) ? 2 : 3;

  if (a & FILE_ATTRIBUTE_DIRECTORY)
    return 1;

  return 0;

#else
  struct stat st;

  if (stat( name, &st ))
    return (errno == ENONENT) ? 3 : 2;

  if (S_ISDIR( st.st_mode ))
    return 1;

  // Could probably refine this.
  return (S_ISREG( st.st_mode )) ? 0 : 2;
#endif
}


int main( int argc, char* argv[] )
{
  char* buf;
  int	buf_size;
  int	flags = DIE_SHOWOPTIONS | DIE_SHOWVERSION;
  int	all = 0;
  int	no_align = 0;
  char* db;
  char* last = NULL;
  int	width = 0, len;
  int	i;

#ifndef _WIN32
  setlocale( LC_ALL, "" );
#endif

  if (argc == 1 || (strcmp( argv[1], "/?" ) == 0 ||
		    strcmp( argv[1], "--help" ) == 0))
  {
    puts( "Detect It Easy Console (Library) by Jason Hood <jadoxa@yahoo.com.au>.\n"
	  "Version " PVERS " (" PDATE ").  Freeware.\n"
	  "\n"
	  "Determine file type by examination of contents.\n"
	  "\n"
	  "diecl [-1aeEnov] [-d DB] FILE...\n"
	  "\n"
	  "-1\tsingle line output\n"
	  "-a\tshow all files (don't ignore unscannable)\n"
	  "-d\tuse DB as the database directory\n"
	  "-e\tshow errors\n"
	  "-E\tshow entropy\n"
	  "-n\tdon't align names (when using -1)\n"
	  "-o\tdon't show options\n"
	  "-v\tdon't show version\n"
	  "\n"
	  "A default database may be chosen with the DIE_DB environment variable." );
    return 0;
  }
  if (argc > 1 && strcmp( argv[1], "--version" ) == 0)
  {
    printf( "diecl version " PVERS " (" PDATE ").  DIE v%s.\n", DIE_version() );
    return 0;
  }

  // Process and remove the options.
  db = getenv( "DIE_DB" );
  for (i = 1; i < argc; ++i)
  {
    if (*argv[i] == '-')
    {
      while (*++argv[i])
      {
	switch (*argv[i])
	{
	  case 'a': all ^= 1; break;
	  case 'n': no_align ^= 1; break;

	  case '1': flags ^= DIE_SINGLELINEOUTPUT|DIE_SHOWFILEFORMATONCE; break;
	  case 'e': flags ^= DIE_SHOWERRORS;  break;
	  case 'E': flags ^= DIE_SHOWENTROPY; break;
	  case 'o': flags ^= DIE_SHOWOPTIONS; break;
	  case 'v': flags ^= DIE_SHOWVERSION; break;

	  case 'd':
	    if (argv[i][1])
	    {
	      db = argv[i] + 1;
	      argv[i] = "";
	    }
	    else
	    {
	      db = argv[++i];
	      if (db)
		argv[i] = "";
	      argv[i-1] = "";
	    }
	    goto next;
	}
      }
    }
  next: ;
  }

  // Find the valid files, the longest name and the last name.
  for (i = 1; i < argc; ++i)
  {
    if (*argv[i] == '\0')
      continue;

    if (!all && status( argv[i] ))
    {
      *argv[i] = '\0';
      continue;
    }
    last = argv[i];
    if (!no_align && (flags & DIE_SINGLELINEOUTPUT))
    {
      len = strlen( argv[i] );
      if (len > width)
	width = len;
    }
  }
  width += 2;

  buf_size = 512;
  buf = malloc( buf_size );

  while (*++argv)
  {
    if (**argv == '\0')
      continue;

    if (all)
    {
      int s = status( *argv );
      switch (s)
      {
	case 0:
	  len = DIE_scanEx( *argv, buf, buf_size, flags, db );
	  break;
	case 1:
	  strcpy( buf, "Directory" );
	  break;
	case 2:
	  strcpy( buf, "Unreadable" );
	  break;
	case 3:
	  strcpy( buf, "Non-existent" );
	  break;
      }
      if (s)
      {
	len = strlen( buf );
	if (!(flags & DIE_SINGLELINEOUTPUT))
	{
	  buf[len++] = '\n';
	  buf[len] = '\0';
	}
      }
    }
    else
    {
      len = DIE_scanEx( *argv, buf, buf_size, flags, db );
    }
    if (len > buf_size)
    {
      free( buf );
      buf_size = (len | 511) + 1;
      buf = malloc( buf_size );
      DIE_scanEx( *argv, buf, buf_size, flags, db );
    }
    if (flags & DIE_SINGLELINEOUTPUT)
    {
      len = printf( "%s", *argv );
      if (no_align)
	len = 0;
      printf( "%-*c%s\n", width - len, ':', buf );
    }
    else
    {
      printf( "%s\n%s", *argv, buf );
      if (*argv != last)
	putchar( '\n' );
    }
    fflush( stdout );
  }

  return 0;
}
