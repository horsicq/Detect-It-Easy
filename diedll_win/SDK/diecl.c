/*
  diecl.c - Lite console version of Detect It Easy.

  Jason Hood, 2, 11, 15 & 26 May, 2014.

  v1.00, 5 June, 2014:
  + help screen;
  + -a option to include all files (non-existent, unreadable, directories).

  v1.01, 3 August, 2014:
  + -d option and DIE_DB environment variable to select database;
  * --version includes DIE's version.

  v1.02, 16 September, 2014:
  + -E option to show entropy.

  Build (VC6):
	cl /nologo /W3 /O2 /MD diecl.c diedll.lib setargv.obj /link /filealign:512
*/

#define PVERS "1.02"
#define PDATE "16 September, 2014"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
  DWORD a;

  a = GetFileAttributes( name );
  if (a == -1)
    return (GetLastError() == ERROR_ACCESS_DENIED) ? 2 : 3;

  if (a & FILE_ATTRIBUTE_DIRECTORY)
    return 1;

  return 0;
}


int main( int argc, char* argv[] )
{
  char buf[512];
  int flags = DIE_SHOWOPTIONS | DIE_SHOWVERSION;
  int all = 0;
  char* db = getenv( "DIE_DB" );
  char* last = NULL;
  int width = 0, len;
  int i;

  if (argc == 1 || (strcmp( argv[1], "/?" ) == 0 ||
		    strcmp( argv[1], "--help" ) == 0))
  {
    puts( "Detect It Easy Console Lite by Jason Hood <jadoxa@yahoo.com.au>.\n"
	  "Version " PVERS " (" PDATE ").  Freeware.\n"
	  "\n"
	  "Determine file type by examination of contents.\n"
	  "\n"
	  "diecl [-1aeEov] [-d DB] FILE...\n"
	  "\n"
	  "-1\tsingle line output\n"
	  "-a\tshow all files (don't ignore unscannable)\n"
	  "-d\tuse DB as the database directory\n"
	  "-e\tshow errors\n"
	  "-E\tshow entropy\n"
	  "-o\tdon't show options\n"
	  "-v\tdon't show version\n"
	  "\n"
	  "A default database may be chosen with the DIE_DB environment variable." );
    return 0;
  }
  if (argc > 1 && strcmp( argv[1], "--version" ) == 0)
  {
    printf( "diecl version " PVERS " (" PDATE ").  DIE v%s.\n",
	    DIE_version() );
    return 0;
  }

  // Process and remove the options.
  for (i = 1; i < argc; ++i)
  {
    if (*argv[i] == '-')
    {
      while (*++argv[i])
      {
	switch (*argv[i])
	{
	  case 'a': all ^= 1; break;
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
    if (flags & DIE_SINGLELINEOUTPUT)
    {
      len = strlen( argv[i] );
      if (len > width)
	width = len;
    }
  }
  width += 2;

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
	  len = DIE_scanEx( *argv, buf, sizeof(buf), flags, db );
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
      len = DIE_scanEx( *argv, buf, sizeof(buf), flags, db );
    }
    if (flags & DIE_SINGLELINEOUTPUT)
    {
      // Ensure proper termination.
      if (len >= sizeof(buf))
	buf[sizeof(buf)-1] = '\0';
      else if (buf[len-2] == ';' && buf[len-1] == ' ')
	buf[len-2] = '\0';
      len = printf( "%s", *argv );
      printf( "%-*c%s\n", width - len, ':', buf );
    }
    else
    {
      if (len >= sizeof(buf))
      {
	buf[sizeof(buf)-2] = '\n';
	buf[sizeof(buf)-1] = '\0';
      }
      printf( "%s\n%s", *argv, buf );
      if (*argv != last)
	putchar( '\n' );
    }
  }

  return 0;
}
