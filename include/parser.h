#ifndef PARSER_H
#define PARSER_H

#include "log_entry.h"

/* Transforme une ligne de texte en LogEntry. Retourne 1 si valide, 0 sinon. */
int parse_log_line(const char *line, LogEntry *entry);

#endif
