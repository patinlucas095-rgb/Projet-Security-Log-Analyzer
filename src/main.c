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
    //const char *path = (argc > 1) ? argv[1] : "data/events.log";
    //que vaut path ?
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        printf("Erreur : impossible d'ouvrir %s\n", path);
        return EXIT_FAILURE;
    }

    size_t capacity = count_lines(file);
    Analyzer analyzer;

    if (!analyzer_init(&analyzer, capacity)) {
        printf("Erreur d'allocation memoire.\n");
        fclose(file);
        return EXIT_FAILURE;
    }

    char line[LINE_BUFFER_SIZE];
    LogEntry entry;

    while (fgets(line, sizeof(line), file) != NULL) {
        analyzer.total_lines++;

        if (parse_log_line(line, &entry)) {
            if (!analyzer_process_entry(&analyzer, &entry)) {
                printf("Erreur pendant l'analyse.\n");
                analyzer_free(&analyzer);
                fclose(file);
                return EXIT_FAILURE;
            }
        } else {
            analyzer_record_invalid_line(&analyzer);
        }
    }

    print_report(&analyzer);

    analyzer_free(&analyzer);
    fclose(file);

    return EXIT_SUCCESS;
}
