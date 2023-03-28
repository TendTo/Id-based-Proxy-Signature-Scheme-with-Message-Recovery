#ifndef DEFINE_H
#define DEFINE_H

#ifndef VERSION
#define VERSION "0.1"
#endif
#ifndef PROJECT_NAME
#define PROJECT_NAME "IdSignature"
#endif

// Usage tooltip
#define USAGE \
    "Usage: %s \n\
Use -h to know more informations\n"

// Help tooltip
#define HELP_TOOLTIP \
    "---------------------------------------------------------------------\n\
" PROJECT_NAME ", version " VERSION "\n\
Usage: %s \n\
---------------------------------------------------------------------\n\
-h   -  shows the help tooltip\n\
-v   -  use verbose output\n"

#endif