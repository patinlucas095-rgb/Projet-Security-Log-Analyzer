#include <stdio.h>

#include "report.h"

void print_report(const Analyzer *analyzer) {
    if (analyzer == NULL) {
        return;
    }

    /* TODO : afficher les statistiques, les maxima et les alertes. */
    printf("===== SECURITY LOG ANALYZER =====\n");
}
