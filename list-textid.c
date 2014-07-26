/*
   CHANGE HISTORY
   ------------------------------------------------------------------------------------------------------------------- 
    29/03/2012 Yang Ming  Init version. Support -a and -u with color output
                          -a  list all TEXT IDs and unicodes contain specified text
                          -u  list all TEXT IDs and text contain specified unicode

                          e.g. see -a English
                               see -u 0045006E0067006C0069007300680000
    30/03/2012 Yang Ming Support -l option
                           -l  list all TEXT IDs in difference language data files
                         Support output all TEXT IDs in difference language data files with specified length and above
   ------------------------------------------------------------------------------------------------------------------- 
   HOW TO BUILD
     gcc -Wall ct.c -o see
  --------------------------------------------------------------------------------------------------------------------
  TODO:
 -	User can specify the path of english-gb_text.dat
 -	Upload it to Nokia source and everyone can get/update/release it via git.
 -	List all source files that using the text id.
 -  Check if a dat file is valid to go through.Currently. I use black list to skip files.
    like optimization_do_dll_big(see search_textid_in_dir).dat.It's not good
  --------------------------------------------------------------------------------------------------------------------
   Test Example:
    68,65,6c,6c,6f = hello (ascii)
    fe,ff,00,68,00,65,00,6c,00,6c,00,6f = hello (big-endian)
    ff,fe,68,00,65,00,6c,00,6c,00,6f,00 = hello (little-endian)
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>

#define red   "\033[0;31m"        /* 0 -> normal ;  31 -> red */
#define cyan  "\033[1;36m"        /* 1 -> bold ;  36 -> cyan */
#define green "\033[4;32m"        /* 4 -> underline ;  32 -> green */
#define blue  "\033[9;34m"        /* 9 -> strike ;  34 -> blue */
#define black  "\033[0;30m"
#define brown  "\033[0;33m"
#define magenta  "\033[0;35m"
#define gray  "\033[0;37m"
#define none   "\033[0m"        /* to flush the previous property */

static int dbg_print_byte(char * in, unsigned int len);
static int unicode_2_ascii(char *ascii, int ascii_len, unsigned char *unicode, int unicode_len);

static void ascii_2_unicode( char *ascii, int nbc, unsigned char *unicode );

static char char_2_hex(char c);
static char hex_2_char(char nibble);

static char * bytes_2_hexstring(char *bytes, int buflen);
static char * hexstring_2_bytes(char *inhex);
static char * hexstring_4byte_2_2bytes(char *bytes);

static void search_textid_in_dir(const char * dir_path,const char * text_id,unsigned int len);
static void search_textid_in_file(const char * file_path,const char * text_id,unsigned int len);

static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static int byteMapLen = sizeof(byteMap);

#define GREP_COMMAND "grep --color -r -i -s -Hn "
#define DAT_FILE_PATH " ./ppm/english-gb_txt.dat"
#define MAX_TEXTID_LEN 64

int main(int argc, char * argv[])
{
    unsigned char * unicode;
    char * newstr1;
    char * newstr2;
    char * cmd;
 
    char dir_path[PATH_MAX] = {0};
    char text_id[MAX_TEXTID_LEN] = {0};
    unsigned int len = 0;
    char * str_len = NULL;
    char * endptr = NULL;   

////////////////////////////////////////////////////////////////////////
    switch(argc)
    {
        case 2:   /* e.g. $lsd --help */ 
            if (argv[1][0] == '-' && 
                argv[1][1] == '-' &&
                argv[1][2] == 'h' &&
                argv[1][3] == 'e' &&
                argv[1][4] == 'l' &&
                argv[1][5] == 'p') 
            {
                fprintf(stdout, "Usage: see -a <text> \n");
                fprintf(stdout, "  or:  see -u <unicode>\n");
                fprintf(stdout, "  or:  see -l <path> <text id> [length]\n");
                fprintf(stdout, "           <path>: the path of text files\r\n");
                fprintf(stdout, "           <text id>: the text id,like qtn_radio_fm_freq_indicator(case insensitive)\r\n");
                fprintf(stdout, "           [length]: only show the text items with larger length than it\r\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "    -a  list all TEXT IDs and unicodes contain specified text\n");
                fprintf(stdout, "    -u  list all TEXT IDs and text contain specified unicode\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "For example:\n");
                fprintf(stdout, "  $see -a English\n");
                fprintf(stdout, "  Input text:English\n");
                fprintf(stdout, "  Unicode:0045006E0067006C006900730068\n");
                fprintf(stdout, "  --------------------------------------------------------\n");
                fprintf(stdout, "    ./ppm/english-gb_txt.dat:6:TEXT_LANGUAGE_NAME \"0045006E0067006C0069007300680000\"\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "  $see -a 'Predictive English'\n");
                fprintf(stdout, "  Input text:Predictive English\n");
                fprintf(stdout, "  Unicode:005000720065006400690063007400690076006500200045006E0067006C006900730068\n");
                fprintf(stdout, "  --------------------------------------------------------\n");
                fprintf(stdout, "  ./ppm/english-gb_txt.dat:3529:QTN_INPUT_ENGLISH_PRED \"005000720065006400690063007400690076006500200045006E0067006C006900730068\"\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "  $see -u 0045006E0067006C0069007300680000\n");
                fprintf(stdout, "  Input unicode:0045006E0067006C0069007300680000\n");
                fprintf(stdout, "  Text:English\n");
                fprintf(stdout, "  --------------------------------------------------------\n");
                fprintf(stdout, "  ./ppm/english-gb_txt.dat:6:TEXT_LANGUAGE_NAME \"0045006E0067006C0069007300680000\"\n");
                fprintf(stdout, "  ./ppm/english-gb_txt.dat:11892:TEXT_USIM_LANGUAGE_NAME \"0045006E0067006C0069007300680000\"\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "  Search the text id,qtn_radio_fm_freq_indicator,and only list the text items that larger than 10\r\n");
                fprintf(stdout, "  $see -l ./ppm qtn_radio_fm_freq_indicator 10 \r\n");
            } else {
                goto MISSING_FILE_OPERAND;
            }
            break;

        case 3:
            //TODO: check if argv[2] is a valid input...
            
            if (argv[1][0] == '-' && argv[1][1] =='a') {                  /* -a option */
                fprintf(stdout, "Input text:%s%s%s\n",cyan,argv[2],none);
                unicode = malloc(strlen(argv[2])*2+2);                
                ascii_2_unicode(argv[2],strlen(argv[2]),unicode);
                fprintf(stdout, "Unicode:");
                dbg_print_byte((char *)unicode,strlen(argv[2])*2);
                fprintf(stdout, "--------------------------------------------------------\n");
                newstr1 = bytes_2_hexstring((char*)unicode,(int)strlen(argv[2])*2);
                cmd = malloc(strlen(GREP_COMMAND)+strlen(DAT_FILE_PATH)+1+strlen(newstr1));
                sprintf(cmd,"%s%s%s",GREP_COMMAND,newstr1,DAT_FILE_PATH);
                system(cmd);

                free(newstr1);
                free(unicode);
              
            } else if (argv[1][0] == '-' && argv[1][1] =='u') {           /* -u option */
                fprintf(stdout, "Input unicode:%s%s%s\n",cyan,argv[2],none);

                newstr1 = hexstring_4byte_2_2bytes(argv[2]);
                newstr2 = hexstring_2_bytes(newstr1);

                fprintf(stdout, "Text:%s%s%s\n",cyan,newstr2,none);
                fprintf(stdout, "--------------------------------------------------------\n");

                cmd = malloc(strlen(GREP_COMMAND)+strlen(DAT_FILE_PATH)+1+strlen(argv[2]));
                sprintf(cmd,"%s%s%s",GREP_COMMAND,argv[2],DAT_FILE_PATH);
                system(cmd);

                free(newstr1);
                free(newstr2);
            }
            break;

       case 4:
           if (argv[1][0] == '-' && argv[1][1] =='l') {                   /* -l option, output all matched text ids with difference language */
               if (strlen(argv[2]) != 0 && strlen(argv[3]) != 0) {

                   if( argv[2][strlen(argv[2])-1] == '/' ) {
                       argv[2][strlen(argv[2])-1] = '\0';
                   } 

                   strncpy(dir_path,argv[2],PATH_MAX);
                   strncpy(text_id,argv[3],MAX_TEXTID_LEN);
                   search_textid_in_dir(dir_path,text_id,0);
               }
           }
           break;

       case 5:
           if (argv[1][0] == '-' && argv[1][1] =='l') {                   /* -l option, output all matched text ids with bigger specified 
                                                                              length in difference language */
               if (strlen(argv[2]) != 0 && strlen(argv[3]) != 0) {

                   if( argv[2][strlen(argv[2])-1] == '/' ) {
                       argv[2][strlen(argv[2])-1] = '\0';
                   } 

                   strncpy(dir_path,argv[2],PATH_MAX);
                   strncpy(text_id,argv[3],MAX_TEXTID_LEN);

                   str_len = argv[4];

                   /* To distinguish success/failure after call */
                   errno = 0;
                   len = strtol(str_len, &endptr, 10);

                   /* Check for various possible errors */
                   if ( errno == ERANGE || 
                        (errno != 0 && len == 0) )  {
                       exit(EXIT_FAILURE);
                   }

                   if (endptr == str_len) {
                       exit(EXIT_FAILURE);
                   }

                   search_textid_in_dir(dir_path,text_id,len);
               }
           }
           break;

       default:
MISSING_FILE_OPERAND:
           fprintf(stdout, "see: missing usage\n");
           fprintf(stdout, "Try `see --help' for more information.\n");
           break;
    }

////////////////////////////////////////////////////////////////////////

#ifdef QUICK_TEST
    char * newstr1;
    char * newstr2;

    char str[] = "hello";
    unsigned char unicode[(sizeof(str)*2)+1];

    /* color text output */
    printf("%sHello, %sworld!%s\n", red, blue, none);
    printf("%sHello%s, %sworld!\n", green, none, cyan);
    printf("%s", none);

    //char unicode2[] = {0x00,0x68,0x00,0x65,0x00,0x6c,0x00,0x6c,0x00,0x6f,0x00,0x00};
    //char unicode2[] = "00680065006C006C006F0000";

    //char str2[64] = {0};   
    //int len = 0;

    fprintf(stdout, "test1. ascii text to unicode string, ascii is %s\n",str);
    ascii_2_unicode(str,sizeof(str),unicode);
    dbg_print_byte((char *)unicode,sizeof(str)*2);

   
    //len = unicode_2_ascii(str2,64,(unsigned char*)unicode2,6);
    //fprintf("len=%d\n",len);
    //dbg_print_byte(str2,len);

    fprintf(stdout, "test2. unicode string to ascii text, unicode string is %s\n","00680065006C006C006F0000");
    newstr1 = hexstring_4byte_2_2bytes("00680065006C006C006F0000");
    fprintf(stdout, "newstr1=%s\n",newstr1);

    newstr2 = hexstring_2_bytes(newstr1);
    free(newstr1);
    
    fprintf(stdout, "newstr2=%s\n",newstr2);
    free(newstr2);
#endif

    return 0;
}

/* 
   Remove high 2 characters('00') from hex unicode string 
   e.g. 00680065006c006c006f -> 68656c6c6f        
 */
static char * hexstring_4byte_2_2bytes(char *bytes)
{
    char *retval = NULL;
    int i, j = 0;

    if (bytes != NULL) {
        retval = malloc( (strlen(bytes)/2)+1 );
        for (i = 2; i < strlen(bytes);i+=4) {
            retval[j++] = bytes[i];
            retval[j++] = bytes[i+1];
        }

        retval[j] = '\0';
    }

    return retval;
}

/* Convert nibbles (4 bit values) into a hex character representation */
static char hex_2_char(char nibble)
{
    if (nibble < byteMapLen) {
        return byteMap[(unsigned int)nibble];
    }

    return '*';
}

/* Convert a buffer of binary values into a hex string representation */
static char * bytes_2_hexstring(char *bytes, int buflen)
{
    char *retval;
    int i;
	
    retval = malloc(buflen*2 + 1);
    for (i = 0; i < buflen; i++) {
        retval[i*2]   = hex_2_char(bytes[i] >> 4);
        retval[i*2+1] = hex_2_char(bytes[i] & 0x0f);
    }
    retval[buflen*2] = '\0';

    return retval;
}

/* Convert hex character representation to their NIBBLE(4 bit,1 byte) values */
static char char_2_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 255;
}

/* Convert a string of characters representing a hex buffer into a series of bytes of that real value */
static char * hexstring_2_bytes(char *inhex)
{
    char *retval;
    char *p;
    int len, i;
	
    len = strlen(inhex) / 2;
    retval = malloc(len+1);
    for (i=0, p = (char *) inhex; i<len; i++) {
        retval[i] = (char_2_hex(*p) << 4) | char_2_hex(*(p+1));
        p += 2;
    }

    retval[len] = 0;
    return retval;
}
	

static void ascii_2_unicode( char *ascii, int nbc, unsigned char *unicode )
{
    int i;

    bzero( unicode, nbc * 2 );
    for ( i = 0; i < nbc; i++ ) {
        unicode[i*2+1] = ascii[i];
    }
}

static int unicode_2_ascii(char *ascii,              /* out */
                           int ascii_len,            /* in  */          
                           unsigned char *unicode,   /* in  */
                           int unicode_len)          /* in  */ 
{
    int i = 0, j = 0;

    for (i = 0; i < unicode_len; i++) {
        ascii[j++] = unicode[i*2+1];
    }

    return j;
}

static int dbg_print_byte(char * in, unsigned int len)
{
    int i = len, j = 0;

    while (i--) {
       fprintf(stdout, "%s%02X",cyan,in[j++]);
    }

    fprintf(stdout, "%s\r\n",none);

    return j;
}

static void search_textid_in_file(const char * file_path,   /* full file path */
                                  const char * text_id,     /* text id,like qtn_radio_fm_freq_indicator(case insensitive) */
                                  unsigned int len)         /* grep value. Only show the text items that has larger length than len */
{
    FILE * logfile = NULL;
    char cursor_block[4012*2] = {0};
    char text_content[4012] = {0};
    int text_len = 0;
    char *ptr = NULL; 
    
    if(!(logfile = fopen(file_path, "r"))) {
        fprintf(stdout, "ERROR: Can not open %s",file_path);
        return;
    }

    while( !feof(logfile) )
    {
       fscanf(logfile,"%s", cursor_block);
       if( strcasecmp(cursor_block,text_id) == 0 )  { /* case insensitive comparing */

           fscanf(logfile,"%s",text_content);
           
           text_len = strlen(text_content)/4;

           if( text_len > 0 &&
               (unsigned int)text_len >= len )  {

               ptr = (char *)text_id; 
               for(ptr = (char *)text_id; *ptr; ptr++)  {
                   *ptr = toupper(*ptr);
               }

               fprintf(stdout, "--------------------------------------------------------------------------------------------------\r\n");
               fprintf(stdout, "File:%s\r\n",file_path);
               fprintf(stdout, "Text ID:%s%s%s\r\n",cyan,text_id,none);
               
               fprintf(stdout, "Text:%s%s%s\r\n",cyan,text_content,none);
               fprintf(stdout, "TEXT LENGTH:%d(unicode)\r\n ",text_len);
           }

           /* No possible have two same text ids in one text file */
           break;
       }       
    }

    fclose(logfile);
}

static void search_textid_in_dir(const char * dir_path,  /* directory path */
                                 const char * text_id,   /* text id,like qtn_radio_fm_freq_indicator(case insensitive) */
                                 unsigned int length)    /* grep value */ 
{
    struct dirent* dirp = NULL;
    DIR* d = NULL;
    char file_path[PATH_MAX] = {0};
    int len;


    if ( (d = opendir(dir_path)) ) {

        while ( (dirp = readdir(d)) != NULL )
        {
           if ( 0 == strcmp( ".", dirp->d_name ) || 0 == strcmp( "..",dirp->d_name ) )  {
               /* skip . and .. */
               continue; 
           }

           /* only scan .dat file. Maybe not OK for S30 source...:-( */
           len = strlen(dirp->d_name);
           if ( len != 0 &&
                len >= 5 && /* min case is x.dat */
                dirp->d_name[len-4] == '.' &&
                (dirp->d_name[len-3] == 'd' || dirp->d_name[len-3] == 'D') &&
                (dirp->d_name[len-2] == 'a' || dirp->d_name[len-2] == 'A') && 
                (dirp->d_name[len-1] == 't' || dirp->d_name[len-1] == 'T') )
           {
               /* skip for files */
               if (strcmp(dirp->d_name,"optimization_do_dll_big.dat") == 0 ||
                   strcmp(dirp->d_name,"optimization_do_dll_little.dat") == 0) {
                   continue; 
               }

               sprintf(file_path,"%s/%s",dir_path,dirp->d_name);
               search_textid_in_file(file_path,text_id,length);
           }
        }
    }

    closedir(d);
}
