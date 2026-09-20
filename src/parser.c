#include <stdio.h>
#include <string.h>
#include "parser.h"

/* Extrait date, heure, type, utilisateur et IP depuis une ligne de log. */
int parse_log_line(const char *line, LogEntry *entry) {
    char temp_type[30]; /* Tableau temporaire pour stocker "LOGIN_SUCCESS" ou "LOGIN_FAILED" */

    /* 
     * sscanf découpe la ligne. 
     * On écrit textuellement "user=%s" et "ip=%s" pour qu'il ignore "user=" et "ip=" 
     * et ne range que la valeur utile dans notre structure.
     */
    int parsed = sscanf(line, "%s %s %s user=%s ip=%s", 
                        entry->date, 
                        entry->time, 
                        temp_type, 
                        entry->user, 
                        entry->ip);

    /* Le contrat demande de retourner 0 si la ligne ne respecte pas le format attendu */
    if (parsed != 5) {
        return 0;
    }

    /* 
     * On convertit la chaine de caracteres en valeur Enum 
     * Cela permet d'utiliser facilement if/switch par la suite au lieu de comparer des chaines 
     */
    if (strcmp(temp_type, "LOGIN_SUCCESS") == 0) {
        entry->type = EVENT_LOGIN_SUCCESS;
    } else if (strcmp(temp_type, "LOGIN_FAILED") == 0) {
        entry->type = EVENT_LOGIN_FAILED;
    } else {
        /* Si l'evenement n'est ni SUCCESS ni FAILED, on considere la ligne invalide */
        return 0;
    }

    /* Le contrat demande de retourner 1 si la ligne est valide et entry rempli */
    return 1;
}