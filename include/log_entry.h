#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#define DATE_LENGTH 11
#define TIME_LENGTH 9
#define USER_LENGTH 64
#define IPV4_LENGTH 16

typedef enum {
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILED,
    EVENT_UNKNOWN
} EventType;

/* Represente une ligne de log valide. */
typedef struct {
    char date[DATE_LENGTH];
    char time[TIME_LENGTH];
    char user[USER_LENGTH];
    char ip[IPV4_LENGTH];
    EventType type;
} LogEntry;


#endif
