

#include <getopt.h>
#include <limits.h>
#include <string.h>

#define _WITH_GETLINE
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


#define MAX_TIMESTAMP_LEN 100


struct useropts {
    int showhdr;
    int minimalview;
    int negate;
    int timeconv;
    char** columns;
    int num_columns;
    const char* ofs;
    const char* timefmt;
};


struct logparams {
    int* out_indexes;
    int num_out_indexes;
    int idx_range;
    int* time_cols;
    char** tmp_fields;
    int num_fields;
    char ifs[2];
    char ofs[2];
    char* unsetf;
    long prev_ts;
};


int usage(void) {
    puts("\nzeek-cut [options] [<columns>]\n");
    puts("Extracts the given columns from ASCII Zeek logs on standard input, and outputs");
    puts("them to standard output. If no columns are given, all are selected.");
    puts("By default, zeek-cut does not include format header blocks in the output.");
    puts("\nExample: cat conn.log | zeek-cut -d ts id.orig_h id.orig_p");
    puts("\n    -c       Include the first format header block in the output.");
    puts("    -C       Include all format header blocks in the output.");
    puts("    -m       Include the first format header blocks in the output in minimal view.");
    puts("    -M       Include all format header blocks in the output in minimal view.");
    puts("    -d       Convert time values into human-readable format.");
    puts("    -D <fmt> Like -d, but specify format for time (see strftime(3) for syntax).");
    puts("    -F <ofs> Sets a different output field separator character.");
    puts("    -h       Show help.");
    puts("    -n       Print all fields *except* those specified.");
    puts("    -u       Like -d, but print timestamps in UTC instead of local time.");
    puts("    -U <fmt> Like -D, but print timestamps in UTC instead of local time.\n");
    puts("For time conversion option -d or -u, the format string can be specified by");
    puts("setting an environment variable ZEEK_CUT_TIMEFMT.\n");
    exit(1);
}

#ifdef _WIN32


char* strsep(char** sp, char* sep) {
    char *p, *s;
    if ( sp == NULL || *sp == NULL || **sp == '\0' )
        return (NULL);
    s = *sp;
    p = s + strcspn(s, sep);
    if ( *p != '\0' )
        *p++ = '\0';
    *sp = p;
    return (s);
}
#endif




int string_index(char* haystack[], int haystack_size, const char* needle) {
    int i;
    for ( i = 0; i < haystack_size; ++i ) {
        if ( ! strcmp(haystack[i], needle) ) {
            return i;
        }
    }
    return -1;
}


char parsesep(const char* sepstr) {
    char ifs;

    if ( ! strncmp(sepstr, "\\x", 2) ) {
        long sepval = strtol(sepstr + 2, NULL, 16);
        ifs = sepval;
    }
    else {
        ifs = sepstr[0];
    }

    return ifs;
}




int find_timecol(const char* line, struct logparams* lp) {
    int i;
    int* tmpptr;
    char* copy_of_line;
    char* field_ptr;
    char* field;

    tmpptr = (int*)realloc(lp->time_cols, lp->idx_range * sizeof(int));
    if ( tmpptr == NULL ) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }

    lp->time_cols = tmpptr;

    if ( (copy_of_line = strdup(line)) == NULL ) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }
    field_ptr = copy_of_line;

    int ret = 0;
    for ( i = 0; i < lp->idx_range; ++i ) {
        if ( (field = strsep(&field_ptr, lp->ifs)) == NULL ) {
            fputs("zeek-cut: log header does not have enough fields\n", stderr);
            ret = 1;
            break;
        }


        lp->time_cols[i] = strcmp("time", field) ? 0 : 1;
    }

    free(copy_of_line);
    return ret;
}







int find_output_indexes(char* line, struct logparams* lp, struct useropts* bopts) {
    int idx;
    int* out_indexes;
    char* field_ptr;
    char* copy_of_line = NULL;
    char* field;


    lp->num_fields = 0;
    field = line;
    while ( (field = strchr(field, lp->ifs[0])) != NULL ) {
        lp->num_fields++;
        field++;
    }
    lp->num_fields++;

    char** tmpptr;

    tmpptr = (char**)realloc(lp->tmp_fields, (lp->num_fields + 1) * sizeof(char*));
    if ( tmpptr == NULL ) {
        return 1;
    }
    lp->tmp_fields = tmpptr;

    if ( bopts->num_columns == 0 ) {

        out_indexes = (int*)realloc(lp->out_indexes, lp->num_fields * sizeof(int));
        if ( out_indexes == NULL ) {
            return 1;
        }

        for ( idx = 0; idx < lp->num_fields; ++idx ) {
            out_indexes[idx] = idx;
        }

        lp->out_indexes = out_indexes;
        lp->idx_range = lp->num_fields;
        lp->num_out_indexes = lp->num_fields;
        return 0;
    }


    if ( (copy_of_line = strdup(line)) == NULL ) {
        return 1;
    }
    field_ptr = copy_of_line;

    idx = 0;
    while ( (field = strsep(&field_ptr, lp->ifs)) != NULL ) {
        lp->tmp_fields[idx++] = field;
    }

    int out_idx = 0;
    int maxval = 0;

    if ( ! bopts->negate ) {

        out_indexes = (int*)realloc(lp->out_indexes, bopts->num_columns * sizeof(int));
        if ( out_indexes == NULL ) {
            return 1;
        }

        for ( idx = 0; idx < bopts->num_columns; ++idx ) {
            out_indexes[idx] = string_index(lp->tmp_fields, lp->num_fields, bopts->columns[idx]);
            if ( out_indexes[idx] > maxval ) {
                maxval = out_indexes[idx];
            }
        }
        out_idx = bopts->num_columns;
    }
    else {

        out_indexes = (int*)realloc(lp->out_indexes, lp->num_fields * sizeof(int));
        if ( out_indexes == NULL ) {
            return 1;
        }

        for ( idx = 0; idx < lp->num_fields; ++idx ) {
            if ( string_index(bopts->columns, bopts->num_columns, lp->tmp_fields[idx]) == -1 ) {
                out_indexes[out_idx++] = idx;
                if ( idx > maxval ) {
                    maxval = idx;
                }
            }
        }
    }

    free(copy_of_line);

    lp->out_indexes = out_indexes;
    lp->idx_range = maxval + 1;
    lp->num_out_indexes = out_idx;
    return 0;
}







void output_time(const char* field, struct logparams* lp, struct useropts* bopts) {

    static char tbuf[MAX_TIMESTAMP_LEN];

    char* tmp;
    long tl = strtol(field, &tmp, 10);

    if ( tl < 0 || tl == LONG_MAX ) {
        fprintf(stderr, "zeek-cut: time value out-of-range: %s\n", field);
    }
    else if ( *tmp != '.' ) {
        if ( strcmp(field, lp->unsetf) ) {

            fprintf(stderr, "zeek-cut: time field is not valid: %s\n", field);
        }
    }
    else if ( tl == lp->prev_ts ) {

        fputs(tbuf, stdout);
        return;
    }
    else {
        time_t tt = tl;
        struct tm tmval;
        struct tm* tmptr;
        tmptr = bopts->timeconv == 1 ? localtime_r(&tt, &tmval) : gmtime_r(&tt, &tmval);

        if ( tmptr ) {
            if ( strftime(tbuf, sizeof(tbuf), bopts->timefmt, tmptr) ) {

                fputs(tbuf, stdout);
                lp->prev_ts = tl;
                return;
            }
            else {
                fputs("zeek-cut: failed to convert timestamp (try a shorter format string)\n", stderr);
            }
        }
        else {

            fprintf(stderr, "zeek-cut: time value out-of-range: %s\n", field);
        }
    }


    fputs(field, stdout);
}




void output_indexes(int hdr, char* line, struct logparams* lp, struct useropts* bopts) {
    int i;
    char* field;
    int dotimeconv = 0;
    int dotimetypeconv = 0;
    int idxrange = lp->idx_range + hdr;
    int firstdone = 0;




    if ( bopts->timeconv && ! hdr ) {
        dotimeconv = 1;
    }

    for ( i = 0; i < idxrange; ++i ) {
        if ( (field = strsep(&line, lp->ifs)) == NULL ) {
            fputs("zeek-cut: skipping log line (not enough fields)\n", stderr);
            return;
        }
        lp->tmp_fields[i] = field;
    }




    if ( bopts->timeconv && hdr && ! strcmp(lp->tmp_fields[0], "#types") ) {
        dotimetypeconv = 1;
    }

    if ( hdr && bopts->minimalview == 0 ) {

        fputs(lp->tmp_fields[0], stdout);
        firstdone = 1;
    }

    for ( i = 0; i < lp->num_out_indexes; ++i ) {
        int idxval = lp->out_indexes[i];

        if ( firstdone )
            fputs(lp->ofs, stdout);

        if ( idxval != -1 ) {
            if ( dotimeconv && lp->time_cols[idxval] ) {

                output_time(lp->tmp_fields[idxval], lp, bopts);
            }
            else if ( dotimetypeconv && ! strcmp("time", lp->tmp_fields[idxval + hdr]) ) {

                fputs("string", stdout);
            }
            else {

                fputs(lp->tmp_fields[idxval + hdr], stdout);
            }
        }




        firstdone = 1;
    }
    putchar('\n');
}





int zeek_cut(struct useropts bopts) {
    int ret = 0;
    struct logparams lp;
    int headers_seen = 0;
    int prev_line_hdr = 0;
    int prev_fields_line = 0;
    ssize_t linelen;
    size_t linesize = 100000;
    char* line = (char*)malloc(linesize);

    if ( line == NULL ) {
        fputs("zeek-cut: out of memory\n", stderr);
        return 1;
    }

    lp.out_indexes = NULL;
    lp.num_out_indexes = 0;
    lp.idx_range = 0;
    lp.time_cols = NULL;
    lp.tmp_fields = NULL;
    lp.num_fields = 0;
    lp.ofs[0] = '\t';
    lp.ofs[1] = '\0';
    lp.ifs[0] = '\t';
    lp.ifs[1] = '\0';
    lp.unsetf = strdup("-");
    lp.prev_ts = -1;

    if ( lp.unsetf == NULL ) {
        fputs("zeek-cut: out of memory\n", stderr);
        free(line);
        return 1;
    }

    while ( (linelen = getline(&line, &linesize, stdin)) > 0 ) {

        line[linelen - 1] = '\0';

        if ( prev_fields_line && strncmp(line, "#types", 6) ) {
            fputs("zeek-cut: bad log header (missing #types line)\n", stderr);
            ret = 1;
            break;
        }


        if ( line[0] != '#' ) {
            prev_line_hdr = 0;
            output_indexes(0, line, &lp, &bopts);
            continue;
        }



        if ( ! prev_line_hdr ) {

            prev_line_hdr = 1;

            if ( headers_seen < 2 ) {
                headers_seen++;
            }
        }

        if ( ! strncmp(line, "#separator ", 11) ) {
            char ifs = parsesep(line + 11);
            if ( ifs == '\0' ) {
                fputs("zeek-cut: bad log header (invalid #separator line)\n", stderr);
                ret = 1;
                break;
            }

            lp.ifs[0] = ifs;




            lp.ofs[0] = bopts.ofs[0] ? bopts.ofs[0] : lp.ifs[0];
        }
        else if ( ! strncmp(line, "#unset_field", 12) ) {
            if ( line[12] && line[13] ) {
                free(lp.unsetf);
                if ( (lp.unsetf = strdup(line + 13)) == NULL ) {
                    fputs("zeek-cut: out of memory\n", stderr);
                    ret = 1;
                    break;
                }
            }
            else {
                fputs("zeek-cut: bad log header (invalid #unset_field line)\n", stderr);
                ret = 1;
                break;
            }
        }
        else if ( ! strncmp(line, "#fields", 7) ) {
            prev_fields_line = 1;
            if ( find_output_indexes(line + 8, &lp, &bopts) ) {
                fputs("zeek-cut: out of memory\n", stderr);
                ret = 1;
                break;
            }
        }
        else if ( ! strncmp(line, "#types", 6) ) {
            if ( ! prev_fields_line ) {
                fputs("zeek-cut: bad log header (missing #fields line)\n", stderr);
                ret = 1;
                break;
            }
            prev_fields_line = 0;

            if ( bopts.timeconv ) {
                if ( find_timecol(line + 7, &lp) ) {
                    ret = 1;
                    break;
                }
            }
        }


        if ( bopts.showhdr >= headers_seen ) {
            if ( ! strncmp(line, "#fields", 7) || (! strncmp(line, "#types", 6) && (bopts.minimalview == 0)) ) {

                output_indexes(1, line, &lp, &bopts);
            }
            else if ( bopts.minimalview == 0 ) {

                puts(line);
            }
        }
    }

    free(lp.time_cols);
    free(lp.out_indexes);
    free(lp.tmp_fields);
    free(lp.unsetf);
    free(line);
    return ret;
}

int main(int argc, char* argv[]) {
    int c;
    char* envtimefmt = getenv("ZEEK_CUT_TIMEFMT");
    if ( envtimefmt == NULL ) {
        envtimefmt = getenv("BRO_CUT_TIMEFMT");
        if ( envtimefmt != NULL )
            fprintf(
                stderr,
                "zeek-cut warning: using legacy environment variable BRO_CUT_TIMEFMT, set ZEEK_CUT_TIMEFMT instead\n");
    }

    struct useropts bopts;
    bopts.showhdr = 0;
    bopts.minimalview = 0;
    bopts.negate = 0;
    bopts.timeconv = 0;
    bopts.ofs = "";
    bopts.timefmt = envtimefmt ? envtimefmt : "%Y-%m-%dT%H:%M:%S%z";

    static struct option long_opts[] = {{"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};

    while ( (c = getopt_long(argc, argv, "cCmMnF:duD:U:h", long_opts, NULL)) != -1 ) {
        switch ( c ) {
            case 'c':
                bopts.minimalview = 0;
                bopts.showhdr = 1;
                break;
            case 'C':
                bopts.minimalview = 0;
                bopts.showhdr = 2;
                break;
            case 'm':
                bopts.minimalview = 1;
                bopts.showhdr = 1;
                break;
            case 'M':
                bopts.minimalview = 1;
                bopts.showhdr = 2;
                break;
            case 'n': bopts.negate = 1; break;
            case 'F':
                if ( strlen(optarg) != 1 ) {
                    fputs("zeek-cut: field separator must be a single character\n", stderr);
                    exit(1);
                }
                bopts.ofs = optarg;
                break;
            case 'd': bopts.timeconv = 1; break;
            case 'u': bopts.timeconv = 2; break;
            case 'D':
                bopts.timeconv = 1;
                bopts.timefmt = optarg;
                break;
            case 'U':
                bopts.timeconv = 2;
                bopts.timefmt = optarg;
                break;
            default: usage(); break;
        }
    }

    if ( bopts.timeconv && strlen(bopts.timefmt) == 0 ) {
        fputs("zeek-cut: time format string cannot be empty\n", stderr);
        exit(1);
    }

    bopts.columns = &argv[optind];
    bopts.num_columns = argc - optind;

    return zeek_cut(bopts);
}
