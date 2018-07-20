/*
  diecl.c - Console version of Detect It Easy using the DLL.

  Jason Hood, 2, 11, 15 & 26 May, 2014.

  v1.00, 5 June, 2014:
  + help screen;
  + -a option to include all files (non-existent, unreadable, directories).

  v1.01, 3 August, 2014:
  + -d option and DIE_DB environment variable to select database;
  * --version includes DIE's version.

  v1.02, 16 September, 2014:
  + -E option to show entropy.

  v1.10, 18 & 19 September, 2014:
  * resize buffer to fit contents;
  + -r option to recurse subdirectories;
  * flush output to work better with a pipe;
  + -n option to prevent single line file name alignment;
  + -b option to add a blank link between recursed directories;
  * use Unicode (for file names; compile with VC10 for better wprintf support);
  * now that it does everything diec does (apart from signature counts), "lite"
     no longer applies - call it "library" instead.

  Build (VC):
	cl /nologo /W3 /O2 /MD diecl.c diedll.lib
*/

#define PVERS "1.10"
#define PDATE "19 September, 2014"

#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "diedll.h"


LPWSTR db;
int    flags = DIE_SHOWOPTIONS | DIE_SHOWVERSION;
int    all;
int    recurse;
int    blank, output;
int    no_align;
char*  buf;
int    buf_size;


// Determine the status of a file:
//   0 - normal
//   1 - directory
//   2 - unreadable
//   3 - doesn't exist
int status( LPCWSTR name )
{
  DWORD a;

  a = GetFileAttributes( name );
  if (a == -1)
    return (GetLastError() == ERROR_ACCESS_DENIED) ? 2 : 3;

  if (a & FILE_ATTRIBUTE_DIRECTORY)
    return 1;

  return 0;
}


static LPWSTR* glob;
static int     globbed, glob_size;
static WCHAR   glob_path[MAX_PATH];
static LPWSTR  glob_name = glob_path;
static DWORD   hidden = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;


int glob_sort( const void* a, const void* b )
{
  return lstrcmpi( *(LPCWSTR*)a, *(LPCWSTR*)b );
}


void add_name( void )
{
  if (globbed >= glob_size)
  {
    glob_size += 128;
    glob = realloc( glob, glob_size * sizeof(LPWSTR) );
  }
  glob[globbed++] = _wcsdup( glob_path );
}


int expand_names( int argc, LPWSTR argv[] )
{
  HANDLE fh;
  WIN32_FIND_DATA fd;
  LPWSTR path, name;
  int	 first;
  int	 keep;
  int	 i;

  for (i = 0; i < globbed; ++i)
    free( glob[i] );

  globbed = 0;
  for (i = 0; i < argc; ++i)
  {
    if (*argv[i] == '\0')
      continue;

    wcscpy( glob_name, argv[i] );
    keep = (all && !recurse &&
	    glob_name == glob_path && wcspbrk( glob_name, L"*?" ) == NULL);
    fh = FindFirstFile( glob_path, &fd );
    if (fh == INVALID_HANDLE_VALUE)
    {
      if (keep)
	add_name();
      continue;
    }

    for (path = name = glob_name; *path; ++path)
      if (*path == '\\' || *path == '/')
	name = path + 1;

    first = globbed;
    do
    {
      if (fd.dwFileAttributes & (hidden | FILE_ATTRIBUTE_DIRECTORY))
      {
	if (keep)
	  add_name();
	continue;
      }
      wcscpy( name, fd.cFileName );
      add_name();
    } while (FindNextFile( fh, &fd ));
    FindClose( fh );

    qsort( glob + first, globbed - first, sizeof(LPWSTR), glob_sort );
  }

  return (globbed != 0);
}


void scan_dir( int argc, LPWSTR argv[] )
{
  int width, last, len;
  int i;

  if (!expand_names( argc, argv ))
    return;

  // Find the valid files, the longest name and the last name.
  width = 0;
  last	= -1;
  for (i = 0; i < globbed; ++i)
  {
    if (!all && status( glob[i] ))
    {
      *glob[i] = '\0';
      continue;
    }
    last = i;
    if (!no_align && (flags & DIE_SINGLELINEOUTPUT))
    {
      len = wcslen( glob[i] );
      if (len > width)
	width = len;
    }
  }
  width += 2;

  if ((blank || !(flags & DIE_SINGLELINEOUTPUT)) && last != -1)
  {
    if (output)
      putchar( '\n' );
    output = 1;
  }

  for (i = 0; i < globbed; ++i)
  {
    if (*glob[i] == '\0')
      continue;

    if (all)
    {
      int s = status( glob[i] );
      switch (s)
      {
	case 0:
	  len = DIE_scanEx( glob[i], buf, buf_size, flags, db );
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
      len = DIE_scanEx( glob[i], buf, buf_size, flags, db );
    }
    if (len > buf_size)
    {
      free( buf );
      buf_size = (len | 511) + 1;
      buf = malloc( buf_size );
      DIE_scanEx( glob[i], buf, buf_size, flags, db );
    }
    if (flags & DIE_SINGLELINEOUTPUT)
    {
      len = wprintf( L"%s", glob[i] );
      if (no_align)
	len = 0;
      printf( "%-*c%s\n", width - len, ':', buf );
    }
    else
    {
      wprintf( L"%s\n%S", glob[i], buf );
      if (i != last)
	putchar( '\n' );
    }
    fflush( stdout );
  }
}


void scan_dirs( int argc, LPWSTR argv[] )
{
  HANDLE fh;
  WIN32_FIND_DATA fd;
  LPWSTR base;

  wcscpy( glob_name, L"*" );
  fh = FindFirstFile( glob_path, &fd );
  if (fh != INVALID_HANDLE_VALUE)
  {
    do
    {
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      {
	if (fd.dwFileAttributes & hidden)
	  continue;
	if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || (
	    fd.cFileName[1] == '.' && fd.cFileName[2] == '\0')))
	  continue;
	base = glob_name;
	glob_name += _snwprintf( glob_name, MAX_PATH - (glob_name - glob_path),
				 L"%s\\", fd.cFileName );
	scan_dir( argc, argv );
	scan_dirs( argc, argv );
	glob_name = base;
      }
    } while (FindNextFile( fh, &fd ));
    FindClose( fh );
  }
}


int wmain( int argc, wchar_t* argv[] )
{
  int i;

  if (argc == 1 || (wcscmp( argv[1], L"/?" ) == 0 ||
		    wcscmp( argv[1], L"--help" ) == 0))
  {
    puts( "Detect It Easy Console (Library) by Jason Hood <jadoxa@yahoo.com.au>.\n"
	  "Version " PVERS " (" PDATE ").  Freeware.\n"
	  "\n"
	  "Determine file type by examination of contents.\n"
	  "\n"
	  "diecl [-1abeEhnorv] [-d DB] FILE...\n"
	  "\n"
	  "-1\tsingle line output\n"
	  "-a\tshow all files (don't ignore unscannable)\n"
	  "-b\tadd a blank line between directories (when using -r)\n"
	  "-d\tuse DB as the database directory\n"
	  "-e\tshow errors\n"
	  "-E\tshow entropy\n"
	  "-h\tinclude hidden/system files when expanding wildcards\n"
	  "-n\tdon't align names (within a directory, when using -1)\n"
	  "-o\tdon't show options\n"
	  "-r\trecurse into subdirectories (of the current directory)\n"
	  "-v\tdon't show version\n"
	  "\n"
	  "A default database may be chosen with the DIE_DB environment variable." );
    return 0;
  }
  if (argc > 1 && wcscmp( argv[1], L"--version" ) == 0)
  {
    printf( "diecl version " PVERS " (" PDATE ").  DIE v%s.\n", DIE_versionA() );
    return 0;
  }

  // Process and remove the options.
  db = _wgetenv( L"DIE_DB" );
  for (i = 1; i < argc; ++i)
  {
    if (*argv[i] == '-')
    {
      while (*++argv[i])
      {
	switch (*argv[i])
	{
	  case 'a': all ^= 1; break;
	  case 'b': blank ^= 1; break;
	  case 'h': hidden ^= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM; break;
	  case 'n': no_align ^= 1; break;
	  case 'r': recurse ^= 1; break;

	  case '1': flags ^= DIE_SINGLELINEOUTPUT|DIE_SHOWFILEFORMATONCE; break;
	  case 'e': flags ^= DIE_SHOWERRORS;  break;
	  case 'E': flags ^= DIE_SHOWENTROPY; break;
	  case 'o': flags ^= DIE_SHOWOPTIONS; break;
	  case 'v': flags ^= DIE_SHOWVERSION; break;

	  case 'd':
	    if (argv[i][1])
	    {
	      db = argv[i] + 1;
	      argv[i] = L"";
	    }
	    else
	    {
	      db = argv[++i];
	      if (db)
		argv[i] = L"";
	      argv[i-1] = L"";
	    }
	    goto next;
	}
      }
    }
  next: ;
  }

  --argc;
  ++argv;

  buf_size = 512;
  buf = malloc( buf_size );

  scan_dir( argc, argv );
  if (recurse)
    scan_dirs( argc, argv );

  return 0;
}
