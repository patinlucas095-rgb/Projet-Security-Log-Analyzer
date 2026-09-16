#include <stdlib.h>

#include "analyzer.h"

/* Retourne les statistiques de l'IP, en la creant si necessaire. */
static IpStats *get_ip_stats(Analyzer *analyzer, const char *ip) {
    (void)analyzer;
    (void)ip;

    /* TODO : rechercher l'IP, ou l'ajouter dans la prochaine case libre. */
    return NULL;
}

/* Retourne les statistiques de l'utilisateur, en le creant si necessaire. */
static UserStats *get_user_stats(Analyzer *analyzer, const char *user) {
    (void)analyzer;
    (void)user;

    /* TODO : rechercher l'utilisateur, ou l'ajouter. */
    return NULL;
}

int analyzer_init(Analyzer *analyzer, size_t capacity) {
    (void)analyzer;
    (void)capacity;

    /* TODO : malloc des tableaux puis initialisation des compteurs. */
    return 0;
}

void analyzer_record_invalid_line(Analyzer *analyzer) {
    if (analyzer != NULL) {
        analyzer->ignored_lines++;
    }
}

int analyzer_process_entry(Analyzer *analyzer, const LogEntry *entry) {
    if (analyzer == NULL || entry == NULL) {
        return 0;
    }

    IpStats *ip_stats = get_ip_stats(analyzer, entry->ip);
    UserStats *user_stats = get_user_stats(analyzer, entry->user);

    if (ip_stats == NULL || user_stats == NULL) {
        return 0;
    }

    /* TODO : mettre a jour les compteurs globaux, IP et utilisateur. */
    return 1;
}

void analyzer_free(Analyzer *analyzer) {
    if (analyzer == NULL) {
        return;
    }

    /* TODO : liberer les tableaux alloues avec malloc. */
}

const IpStats *analyzer_top_ip(const Analyzer *analyzer) {
    (void)analyzer;

    /* TODO : trouver l'IP ayant le plus d'echecs. */
    return NULL;
}

const UserStats *analyzer_top_user(const Analyzer *analyzer) {
    (void)analyzer;

    /* TODO : trouver l'utilisateur ayant le plus d'echecs. */
    return NULL;
}
