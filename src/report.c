#include <stdio.h>
#include "report.h"
#include "analyzer.h"

void print_report(const Analyzer *analyzer) {
    if (analyzer == NULL) {
        return;
    }

    printf("===== SECURITY LOG ANALYZER =====\n");
    
    /* 1. Statistiques globales (utilisation des variables exactes de analyzer.h) */
    printf("Lignes lues           : %zu\n", analyzer->total_lines);
    printf("Evenements valides    : %zu\n", analyzer->valid_events);
    printf("Lignes ignorees       : %zu\n", analyzer->ignored_lines);
    printf("Connexions reussies   : %zu\n", analyzer->login_successes);
    printf("Connexions echouees   : %zu\n", analyzer->login_failures);
    printf("IP distinctes         : %zu\n", analyzer->ip_count);
    printf("Utilisateurs          : %zu\n", analyzer->user_count);
    
    printf("\n");
    
    /* 2. Recuperation des Maxima via les fonctions de analyzer.h */
    const IpStats *top_ip = analyzer_top_ip(analyzer);
    if (top_ip != NULL) {
        printf("IP avec le plus d'echecs: %s (%d)\n", top_ip->ip, top_ip->failures);
    }

    const UserStats *top_user = analyzer_top_user(analyzer);
    if (top_user != NULL) {
        printf("Utilisateur le plus cible %s (%d echecs)\n", top_user->user, top_user->failures);
    }
           
    printf("\nAlertes:\n");
    
    /* 3. Detection a la volee des alertes de force brute */
    for (size_t i = 0; i < analyzer->ip_count; i++) {
        if (analyzer->ips[i].max_failure_streak >= BRUTE_FORCE_THRESHOLD) {
            printf("[BRUTE_FORCE] %s serie maximale %d echecs\n", 
                   analyzer->ips[i].ip, 
                   analyzer->ips[i].max_failure_streak);
        }
    }
}