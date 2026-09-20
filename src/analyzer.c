#include <stdlib.h>
#include <string.h>
#include "analyzer.h"

/* Fonction interne : cherche une IP ou l'ajoute si elle n'existe pas */
static IpStats *get_ip_stats(Analyzer *analyzer, const char *ip) {
    for (size_t i = 0; i < analyzer->ip_count; i++) {
        if (strcmp(analyzer->ips[i].ip, ip) == 0) {
            return &analyzer->ips[i];
        }
    }
    
    if (analyzer->ip_count < analyzer->capacity) {
        IpStats *new_ip = &analyzer->ips[analyzer->ip_count];
        strcpy(new_ip->ip, ip);
        new_ip->successes = 0;
        new_ip->failures = 0;
        new_ip->current_failure_streak = 0;
        new_ip->max_failure_streak = 0;
        analyzer->ip_count++;
        return new_ip;
    }
    return NULL;
}

/* Fonction interne : cherche un utilisateur ou l'ajoute */
static UserStats *get_user_stats(Analyzer *analyzer, const char *user) {
    for (size_t i = 0; i < analyzer->user_count; i++) {
        if (strcmp(analyzer->users[i].user, user) == 0) {
            return &analyzer->users[i];
        }
    }
    
    if (analyzer->user_count < analyzer->capacity) {
        UserStats *new_user = &analyzer->users[analyzer->user_count];
        strcpy(new_user->user, user);
        new_user->successes = 0;
        new_user->failures = 0;
        analyzer->user_count++;
        return new_user;
    }
    return NULL;
}

int analyzer_init(Analyzer *analyzer, size_t capacity) {
    if (analyzer == NULL) return 0;

    analyzer->total_lines = 0;
    analyzer->valid_events = 0;
    analyzer->ignored_lines = 0;
    analyzer->login_successes = 0;
    analyzer->login_failures = 0;
    
    analyzer->ip_count = 0;
    analyzer->user_count = 0;
    analyzer->capacity = capacity;

    analyzer->ips = malloc(capacity * sizeof(IpStats));
    analyzer->users = malloc(capacity * sizeof(UserStats));

    if (analyzer->ips == NULL || analyzer->users == NULL) {
        analyzer_free(analyzer);
        return 0;
    }
    return 1;
}

void analyzer_record_invalid_line(Analyzer *analyzer) {
    if (analyzer != NULL) {
        analyzer->ignored_lines++;
    }
}

int analyzer_process_entry(Analyzer *analyzer, const LogEntry *entry) {
    if (analyzer == NULL || entry == NULL) return 0;

    IpStats *ip_stats = get_ip_stats(analyzer, entry->ip);
    UserStats *user_stats = get_user_stats(analyzer, entry->user);

    if (ip_stats == NULL || user_stats == NULL) return 0;

    analyzer->valid_events++;

    if (entry->type == EVENT_LOGIN_SUCCESS) {
        analyzer->login_successes++;
        ip_stats->successes++;
        user_stats->successes++;
        ip_stats->current_failure_streak = 0; /* Remise a zero en cas de succes */
    } 
    else if (entry->type == EVENT_LOGIN_FAILED) {
        analyzer->login_failures++;
        ip_stats->failures++;
        user_stats->failures++;
        ip_stats->current_failure_streak++;
        
        if (ip_stats->current_failure_streak > ip_stats->max_failure_streak) {
            ip_stats->max_failure_streak = ip_stats->current_failure_streak;
        }
    }

    return 1;
}

void analyzer_free(Analyzer *analyzer) {
    if (analyzer == NULL) return;
    free(analyzer->ips);
    free(analyzer->users);
    analyzer->ips = NULL;
    analyzer->users = NULL;
}

const IpStats *analyzer_top_ip(const Analyzer *analyzer) {
    if (analyzer == NULL || analyzer->ip_count == 0) return NULL;
    
    const IpStats *top = &analyzer->ips[0];
    for (size_t i = 1; i < analyzer->ip_count; i++) {
        if (analyzer->ips[i].failures > top->failures) {
            top = &analyzer->ips[i];
        }
    }
    return top;
}

const UserStats *analyzer_top_user(const Analyzer *analyzer) {
    if (analyzer == NULL || analyzer->user_count == 0) return NULL;
    
    const UserStats *top = &analyzer->users[0];
    for (size_t i = 1; i < analyzer->user_count; i++) {
        if (analyzer->users[i].failures > top->failures) {
            top = &analyzer->users[i];
        }
    }
    return top;
}