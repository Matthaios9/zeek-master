// fnmatch.cpp
// Copyright (c) 2022/10/19 Tomer Lev <tomerlev@microsoft.com>
// License open source MIT

#include "fnmatch.h"

// POSIX-compatible fnmatch supporting *, ?, [...], [!...], and [a-z] ranges.
// Replaces PathMatchSpecA which did not handle bracket expressions.
int fnmatch(const char *pattern, const char *string, int flags)
{
	while ( *pattern )
	{
		switch ( *pattern )
		{
		case '*':
			++pattern;
			if ( ! *pattern )
				return 0;
			while ( *string )
			{
				if ( fnmatch(pattern, string, flags) == 0 )
					return 0;
				++string;
			}
			return FNM_NOMATCH;

		case '?':
			if ( ! *string )
				return FNM_NOMATCH;
			++string;
			++pattern;
			break;

		case '[':
		{
			if ( ! *string )
				return FNM_NOMATCH;
			++pattern;
			int negate = 0;
			if ( *pattern == '!' || *pattern == '^' )
			{
				negate = 1;
				++pattern;
			}
			int matched = 0;
			while ( *pattern && *pattern != ']' )
			{
				if ( pattern[1] == '-' && pattern[2] && pattern[2] != ']' )
				{
					if ( (unsigned char)*string >= (unsigned char)pattern[0] &&
					     (unsigned char)*string <= (unsigned char)pattern[2] )
						matched = 1;
					pattern += 3;
				}
				else
				{
					if ( *string == *pattern )
						matched = 1;
					++pattern;
				}
			}
			if ( *pattern == ']' )
				++pattern;
			if ( negate )
				matched = !matched;
			if ( ! matched )
				return FNM_NOMATCH;
			++string;
			break;
		}

		default:
			if ( *string != *pattern )
				return FNM_NOMATCH;
			++string;
			++pattern;
			break;
		}
	}
	return *string ? FNM_NOMATCH : 0;
}
