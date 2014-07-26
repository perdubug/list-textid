#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define MAX_TEXTID_LEN 64

void search_textid_in_file(const char * file_path,   /* full file path */
                           const char * text_id,     /* text id,like qtn_radio_fm_freq_indicator(case insensitive) */
                           unsigned int len)         /* grep value. Only show the text items that has larger length than len */
{
    FILE * logfile = NULL;
    char cursor_block[4012*2] = {0};
    char text_content[4012] = {0};
    int text_len = 0;
    
    if(!(logfile = fopen(file_path, "r")))
    {
        printf("ERROR: Can not open %s",file_path);
        return;
    }

    while( !feof(logfile) )
    {
       fscanf(logfile,"%s", cursor_block);
       if( strcasecmp(cursor_block,text_id) == 0 ) /* case insensitive comparing */
       {
           fscanf(logfile,"%s",text_content);
           
           text_len = strlen(text_content)/4;

           if( text_len > 0 &&
               (unsigned int)text_len >= len )
           {
               printf("--------------------------------------------------------------------------------------------------\r\n");
               printf("File:%s\r\n",file_path);
               printf("Text ID:%s  Text:%s\r\n",text_id,text_content);
               printf("TEXT LENGTH:%d(unicode)\r\n ",text_len);
               printf("--------------------------------------------------------------------------------------------------\r\n");
           }

           /* No possible have two same text ids in one text file */
           break;
       }       
    }

    fclose(logfile);
}

void search_textid_in_dir(const char * dir_path,  /* directory path */
                          const char * text_id,   /* text id,like qtn_radio_fm_freq_indicator(case insensitive) */
                          unsigned int len)       /* grep value */ 
{
    struct dirent* dirp = NULL;
    DIR* d = NULL;
    char file_path[PATH_MAX] = {0};


    if ( (d = opendir(dir_path)) )
    {
        while ( (dirp = readdir(d)) != NULL )
        {
           if ( 0 == strcmp( ".", dirp->d_name ) || 0 == strcmp( "..",dirp->d_name ) ) 
           {
               /* skip . and .. */
               continue; 
           }

           sprintf(file_path,"%s/%s",dir_path,dirp->d_name);
           search_textid_in_file(file_path,text_id,len);
        }
    }

    closedir(d);
}

void show_usage(void)
{
    printf("Usage: list-textid <path> <text id> [length]\r\n");
    printf("   <path>: the path of text files\r\n");
    printf("   <text id>: the text id,like qtn_radio_fm_freq_indicator(case insensitive)\r\n");
    printf("   [length]: only show the text items with larger length than it\r\n");
    printf("\r\n");
    printf("For example, search the text id,qtn_radio_fm_freq_indicator,and only list the text items that larger than 10\r\n");
    printf("  $list-textid /home/m7yang/sb8/p3888eu/ppm/texts/simplex qtn_radio_fm_freq_indicator 10 \r\n");
}

int main(int argc, char * argv[])
{
    char dir_path[PATH_MAX] = {0};
    char text_id[MAX_TEXTID_LEN] = {0};
    unsigned int len = 0;
    char * str_len = NULL;
    char * endptr = NULL;

    if (argc < 3)
    {
        show_usage();
        exit(EXIT_FAILURE);
    }

    strncpy(dir_path,argv[1],PATH_MAX);
    strncpy(text_id,argv[2],MAX_TEXTID_LEN);

    if (argc >=4)
    {
        str_len = argv[3];

        /* To distinguish success/failure after call */
        errno = 0;
        len = strtol(str_len, &endptr, 10);

        /* Check for various possible errors */
        if ((errno == ERANGE && (len == LONG_MAX || len == LONG_MIN))
             || (errno != 0 && len == 0)) 
        {
            show_usage();
            exit(EXIT_FAILURE);
        }

        if (endptr == str_len) 
        {
            show_usage();
            exit(EXIT_FAILURE);
        }
    }

    search_textid_in_dir(dir_path,text_id,len);
    return 0;
}

