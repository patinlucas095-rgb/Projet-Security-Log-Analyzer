#include <stdio.h>
#include <stdlib.h>

#include "analyzer.h"
#include "parser.h"
#include "report.h"

#define LINE_BUFFER_SIZE 512

/* Compte les lignes puis replace le curseur au debut du fichier. */
static size_t count_lines(FILE *file) {
    char line[LINE_BUFFER_SIZE];
    size_t count = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        count++;
    }

    rewind(file);
    return count;
}

int main(int argc, char *argv[]) {
    /* Prend le fichier en argument, sinon par defaut data/events.log */
    const char *path = (argc > 1) ? argv[1] : "data/events.log";
    
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        printf("Erreur : impossible d'ouvrir %s\n", path);
        return EXIT_FAILURE;
    }

    /* Capacite maximale = nombre de lignes du fichier */
    size_t capacity = count_lines(file);
    Analyzer analyzer;

    if (!analyzer_init(&analyzer, capacity)) {
        printf("Erreur d'allocation memoire.\n");
        fclose(file);
        return EXIT_FAILURE;
    }

    char line[LINE_BUFFER_SIZE];
    LogEntry entry;

    /* Boucle principale de lecture */
    while (fgets(line, sizeof(line), file) != NULL) {
        analyzer.total_lines++;

        /* Appel a TON fichier parser.c */
        if (parse_log_line(line, &entry)) {
            if (!analyzer_process_entry(&analyzer, &entry)) {
                printf("Erreur pendant l'analyse d'une ligne.\n");
                analyzer_free(&analyzer);
                fclose(file);
                return EXIT_FAILURE;
            }
        } else {
            analyzer_record_invalid_line(&analyzer);
        }
    }

    /* Appel a TON fichier report.c */
    print_report(&analyzer);

    analyzer_free(&analyzer);
    fclose(file);

    return EXIT_SUCCESS;
}