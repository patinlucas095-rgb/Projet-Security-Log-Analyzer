#ifndef ANALYZER_H
#define ANALYZER_H

#include <stddef.h>
#include "log_entry.h"

#define BRUTE_FORCE_THRESHOLD 5

/* Statistiques cumulees pour une adresse IP. */
typedef struct {
    char ip[IPV4_LENGTH];
    int successes;
    int failures;
    int current_failure_streak;
    int max_failure_streak;
} IpStats;

/* Statistiques cumulees pour un utilisateur. */
typedef struct {
    char user[USER_LENGTH];
    int successes;
    int failures;
} UserStats;

/* Contient toutes les statistiques de l'analyse. */
typedef struct {
    size_t total_lines;
    size_t valid_events;
    size_t ignored_lines;
    size_t login_successes;
    size_t login_failures;

    IpStats *ips;
    size_t ip_count;

    UserStats *users;
    size_t user_count;

    size_t capacity;
} Analyzer;

/* Initialise l'analyseur et alloue les tableaux dynamiques. */
int analyzer_init(Analyzer *analyzer, size_t capacity);

/* Met a jour les statistiques a partir d'un evenement valide. */
int analyzer_process_entry(Analyzer *analyzer, const LogEntry *entry);

void analyzer_record_invalid_line(Analyzer *analyzer);
void analyzer_free(Analyzer *analyzer);

const IpStats *analyzer_top_ip(const Analyzer *analyzer);
const UserStats *analyzer_top_user(const Analyzer *analyzer);

#endif
