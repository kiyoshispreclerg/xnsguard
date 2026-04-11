#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>
#include <sys/wait.h>

#define MAX_ALERTS          100
#define MAX_IGNORED         200
#define BUF_SIZE            4096
#define REPORT_THROTTLE_MS  1000

#define XNOTIFY_ATTACH           1
#define XNOTIFY_SELECTION        2
#define XNOTIFY_COMPOSITE        3
#define XNOTIFY_SCREEN           4
#define XNOTIFY_RECORD           5
#define XNOTIFY_CURSOR           6
#define XNOTIFY_INPUT_GRAB       7
#define XNOTIFY_INPUT_INJECT     8
#define XNOTIFY_HOTKEY           9
#define XNOTIFY_INPUT           10
#define XNOTIFY_TREE            11
#define XNOTIFY_PROP            12

#define COMMAND_HEARTBEAT     1
#define COMMAND_ALLOW_ALL     2
#define COMMAND_ALLOW_ACTION  3
#define COMMAND_DENY          4
#define COMMAND_DENY_ALL      5
#define COMMAND_DENY_ACTION   6
#define COMMAND_ALLOW         0

static const struct {
    int   id;
    const char *name;
} action_names[] = {
    { XNOTIFY_ATTACH,        "ATTACH" },
    { XNOTIFY_SELECTION,     "SELECTION" },
    { XNOTIFY_COMPOSITE,     "COMPOSITE" },
    { XNOTIFY_SCREEN,        "SCREEN" },
    { XNOTIFY_RECORD,        "RECORD" },
    { XNOTIFY_CURSOR,        "CURSOR" },
    { XNOTIFY_INPUT_GRAB,    "INPUT_GRAB" },
    { XNOTIFY_INPUT_INJECT,  "INPUT_INJECT" },
    { XNOTIFY_HOTKEY,        "HOTKEY" },
    { XNOTIFY_INPUT,         "INPUT" },
    { XNOTIFY_TREE,          "TREE" },
    { XNOTIFY_PROP,          "PROP" },
    { 0, NULL }
};

static const struct {
    int   id;
    const char *name;
} action_descriptions[] = {
    { XNOTIFY_ATTACH,        "Access X server shared memory" },
    { XNOTIFY_SELECTION,     "Access clipboard" },
    { XNOTIFY_COMPOSITE,     "Access other windows" },
    { XNOTIFY_SCREEN,        "Capture the screen" },
    { XNOTIFY_RECORD,        "Capture events - like keystrokes" },
    { XNOTIFY_CURSOR,        "Access cursor (mouse)" },
    { XNOTIFY_INPUT_GRAB,    "Capture mouse or keyboard" },
    { XNOTIFY_INPUT_INJECT,  "Insert keystrokes" },
    { XNOTIFY_HOTKEY,        "Register global hotkeys" },
    { XNOTIFY_INPUT,         "Capture input - even when unfocused" },
    { XNOTIFY_TREE,          "List open windows" },
    { XNOTIFY_PROP,          "Access properties of other windows" },
    { 0, NULL }
};

static const char* action_to_string(int action_id) {
    if (action_id == -1)
        return "ALL";

    for (int i = 0; action_names[i].id > 0; i++) {
        if (action_names[i].id == action_id)
            return action_names[i].name;
    }
    return "UNKNOWN";
}

static const char* action_to_description(int action_id) {
    if (action_id == -1)
        return "All the X server permissions";

    for (int i = 0; action_descriptions[i].id > 0; i++) {
        if (action_descriptions[i].id == action_id)
            return action_descriptions[i].name;
    }
    return "UNKNOWN";
}

static int string_to_action(const char *str) {
    if (!str) return 0;
    if (strcasecmp(str, "ALL") == 0)
            return -1;

    for (int i = 0; action_names[i].name; i++) {
        if (strcasecmp(str, action_names[i].name) == 0)
            return action_names[i].id;
    }
    return 0;
}

static char SOCKET_PATH_BUF[108] = {0};
static char LOCK_SOCKET_PATH_BUF[108] = {0};
static int lock_fd = -1;
static int server_fd = -1;
static pthread_t file_monitor_thread;
static pthread_t processor_thread;
static volatile int should_exit = 0;

static int no_pause_mode = 0;      /* 1 = notify only, no SIGSTOP */
static int quiet_mode = 0;         /* 1 = no Zenity, terminal logs only */
static int always_kill_mode = 0;   /* 1 = kill unknown processes immediately */
static int log_level = 2;          /* 0=silent, 1=clean, 2=normal, 3=verbose, 4=debug */

static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ignored_lock = PTHREAD_MUTEX_INITIALIZER;

struct Alert {
    int action;
    pid_t pid;
    char  exe[PATH_MAX];
    char time_str[20];
    int paused;
};

struct Alert alert_queue[MAX_ALERTS];
int alert_count = 0;

struct IgnoredEntry {
    char exe_pattern[PATH_MAX];
    char action[64];
    int  rule_type;   /* 0 = ALLOW, 1 = DENY */
};

struct IgnoredEntry ignored_cmds[MAX_IGNORED];
int ignored_count = 0;

static char config_dir[256] = "";
static char perms_file[512] = {0};
static time_t last_config_mtime = 0;

static char ignore_file[512] = {0};
static time_t last_ignore_mtime = 0;

struct IgnoredReport {
    char exe[PATH_MAX];
};

static struct IgnoredReport ignored_reports[MAX_IGNORED];
static int ignored_reports_count = 0;
static pthread_mutex_t report_ignore_lock = PTHREAD_MUTEX_INITIALIZER;

struct SeenAlert {
    char exe[PATH_MAX];
    pid_t pid;
    int action;
};

struct SeenAlert seen_alerts[MAX_ALERTS];
int seen_count = 0;

static struct {
    char  exe[PATH_MAX];
    int   action;
    time_t  last_time;
} last_report = {0};

/* ====================== LOGGING ====================== */

char* get_current_time() {
    static char buf[20];
    time_t now = time(NULL);
    strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&now));
    return buf;
}

void log_msg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[%s] ", get_current_time());
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

static void log_filtered(int min_level, const char *format, ...) {
    if (log_level < min_level) return;
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[%s] ", get_current_time());
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* ====================== UTILITIES ====================== */

char* trim(char *str) {
    char *end;
    while (*str == ' ' || *str == '\t') str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t')) end--;
    *(end + 1) = 0;
    return str;
}

time_t get_config_max_mtime(void) {
    time_t max_t = 0;
    struct stat st;
    if (stat(perms_file, &st) == 0 && st.st_mtime > max_t) max_t = st.st_mtime;
    return max_t;
}

static char *
trim_exe_for_log(const char *full_path)
{
    static char buffer[128];

    if (!full_path || *full_path == '\0') {
        strcpy(buffer, "?");
        return buffer;
    }

    size_t len = strlen(full_path);
    if (len <= 64) { 
        strncpy(buffer, full_path, sizeof(buffer)-1);
        buffer[sizeof(buffer)-1] = '\0';
        return buffer;
    }

    const char *last_slash = strrchr(full_path, '/');
    if (!last_slash) {
        strncpy(buffer, full_path, sizeof(buffer)-1);
        buffer[sizeof(buffer)-1] = '\0';
        return buffer;
    }

    const char *exe_name = last_slash + 1;

    const char *parent_end = last_slash;
    while (parent_end > full_path && *(parent_end-1) != '/')
        parent_end--;
    size_t parent_len = last_slash - parent_end;

    const char *parent_start = (parent_len > 0) ? parent_end : last_slash;

    size_t fixed_len = strlen(exe_name) + parent_len + 5;
    if (fixed_len >= sizeof(buffer)-1)
        fixed_len = sizeof(buffer)-20;

    size_t prefix_max = sizeof(buffer) - fixed_len - 1;

    size_t prefix_len = (size_t)(parent_start - full_path);
    if (prefix_len > prefix_max) {
        strncpy(buffer, full_path, prefix_max - 3);
        strcpy(buffer + prefix_max - 3, "...");
    } else {
        strncpy(buffer, full_path, prefix_len);
        buffer[prefix_len] = '\0';
    }

    strcat(buffer, "/.../");
    if (parent_len > 0) {
        strncat(buffer, parent_start, parent_len);
        strcat(buffer, "/");
    }
    strcat(buffer, exe_name);

    buffer[sizeof(buffer)-1] = '\0';
    return buffer;
}

static int
pattern_matches(const char *exe, const char *pattern) {
    if (!exe || !pattern) return 0;
    if (strcmp(pattern, "*") == 0) return 1;

    size_t plen = strlen(pattern);
    if (plen >= 2 && strcmp(pattern + plen - 2, "/*") == 0) {
        size_t prelen = plen - 2;
        if (strncmp(exe, pattern, prelen) == 0 &&
            (exe[prelen] == '/' || exe[prelen] == '\0'))
            return 1;
        return 0;
    }
    return strcmp(exe, pattern) == 0;
}

/* ====================== CONFIG (USER ONLY) ====================== */

void load_user_config(void) {
    pthread_mutex_lock(&ignored_lock);
    ignored_count = 0;

    FILE *file = fopen(perms_file, "r");
    if (!file) {
        log_filtered(2, "No user config found at %s (normal on first run)", perms_file);
        pthread_mutex_unlock(&ignored_lock);
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        char *trimmed = trim(line);
        if (strlen(trimmed) == 0 || trimmed[0] == '#') continue;

        if (ignored_count >= MAX_IGNORED) {
            log_msg("Warning: maximum number of rules (%d) reached", MAX_IGNORED);
            continue;
        }

        char *cmd = strtok(trimmed, " \t\r\n");
        if (!cmd) continue;

        if (strcasecmp(cmd, "ALLOW") == 0 || strcasecmp(cmd, "DENY") == 0) {
            int is_allow = (strcasecmp(cmd, "ALLOW") == 0);
            char *token1 = strtok(NULL, " \t\r\n");   /* action or ALL */
            char *token2 = strtok(NULL, " \t\r\n");   /* pattern */

            if (!token1) continue;

            int action = string_to_action(token1);

            char pattern[PATH_MAX] = {0};
            char action_name[64] = {0};

            if (action == -1) {                      /* ALL */
                if (token2) {
                    strncpy(pattern, token2, sizeof(pattern)-1);
                    strcpy(ignored_cmds[ignored_count].exe_pattern, pattern);
                    ignored_cmds[ignored_count].action[0] = '\0';
                    ignored_cmds[ignored_count].rule_type = is_allow ? 0 : 1;
                    ignored_count++;
                }
            } else if (action > 0) {
                if (token2) {
                    strncpy(pattern, token2, sizeof(pattern)-1);
                    strncpy(action_name, token1, sizeof(action_name)-1);
                } else {
                    strcpy(pattern, "*");
                    strncpy(action_name, token1, sizeof(action_name)-1);
                }

                strncpy(ignored_cmds[ignored_count].exe_pattern, pattern, sizeof(ignored_cmds[ignored_count].exe_pattern)-1);
                strncpy(ignored_cmds[ignored_count].action, action_name, sizeof(ignored_cmds[ignored_count].action)-1);
                ignored_cmds[ignored_count].rule_type = is_allow ? 0 : 1;
                ignored_count++;
            }
        }
    }
    fclose(file);
    last_config_mtime = time(NULL);
    log_filtered(3, "%d rules loaded", ignored_count);
    pthread_mutex_unlock(&ignored_lock);
}

int get_preconfig_rule(const char *exe, int action_id) {
    if (!exe || *exe == '\0' || strcmp(exe, "?") == 0)
        return 0;

    const char *action_name = action_to_string(action_id);
    if (!action_name || strcmp(action_name, "UNKNOWN") == 0)
        return 0;

    pthread_mutex_lock(&ignored_lock);
    for (int i = 0; i < ignored_count; i++) {
        if (!pattern_matches(exe, ignored_cmds[i].exe_pattern))
            continue;

        if (ignored_cmds[i].action[0] == '\0' || 
            strcasecmp(ignored_cmds[i].action, action_name) == 0) {
            int ret = (ignored_cmds[i].rule_type == 0) ? 1 : 2;
            pthread_mutex_unlock(&ignored_lock);
            return ret;   /* 1=allow, 2=deny */
        }
    }
    pthread_mutex_unlock(&ignored_lock);
    return 0;
}

/* ====================== SYNC PERMISSIONS TO X SERVER ====================== */

void send_all_permissions_to_xserver(void) {
    pthread_mutex_lock(&ignored_lock);

    int sent = 0;
    for (int i = 0; i < ignored_count; i++) {
        const char *pat = ignored_cmds[i].exe_pattern;
        const char *act_str = ignored_cmds[i].action;
        int action_id = string_to_action(act_str);
        
        if (ignored_cmds[i].rule_type == 0) {   /* ALLOW */
            if (act_str[0] == '\0') {
                /* ALLOW ALL <pattern> */
                send_permission(0, pat, 0, COMMAND_ALLOW_ALL);           /* command_type 2 = ALLOW_ALL */
            }
            else if (strcmp(pat, "*") == 0) {
                /* ALLOW <ACTION>  (sem exe → allow_all para essa ação) */
                send_permission(action_id, "", 0, COMMAND_ALLOW_ACTION);
            } else {
                send_permission(action_id, pat, 0, COMMAND_ALLOW);   /* command_type 3 = ALLOW_ACTION */
            }
        } else {   /* DENY */
            if (act_str[0] == '\0') {
                send_permission(0, pat, 0, COMMAND_DENY_ALL);           /* DENY_ALL */
            } else if (strcmp(pat, "*") == 0) {
                send_permission(action_id, "", 0, COMMAND_DENY_ACTION);    /* DENY_ACTION */
            } else {
                send_permission(action_id, pat, 0, COMMAND_DENY);   /* DENY normal */
            }
        }
        sent++;
    }

    pthread_mutex_unlock(&ignored_lock);

    if (sent > 0)
        log_filtered(2, "Full sync: sent %d permission rules to X server", sent);
    else
        log_filtered(3, "Full sync: no rules to send (perms.conf empty)");
}

/* ====================== SAVE RULES ====================== */

void save_rule(const char *exe, int action_id, int is_allow) {
    if (!exe || *exe == '\0') return;

    const char *action_str = action_to_string(action_id);

    pthread_mutex_lock(&ignored_lock);
    for (int i = 0; i < ignored_count; i++) {
        if (strcmp(ignored_cmds[i].exe_pattern, exe) == 0 &&
            strcmp(ignored_cmds[i].action, action_str) == 0) {
            pthread_mutex_unlock(&ignored_lock);
            log_msg("Rule already exists: %s %s %s", is_allow ? "ALLOW" : "DENY", action_str, trim_exe_for_log(exe));
            return;
        }
    }
    pthread_mutex_unlock(&ignored_lock);

    FILE *file = fopen(perms_file, "a");
    if (!file) return;

    fprintf(file, "%s %s %s\n", is_allow ? "ALLOW" : "DENY", action_str, exe);
    fclose(file);
    load_user_config();
}

void save_denied_entry(const char *exe, int action_id) {
    save_rule(exe, action_id, 0);   /* is_allow = false */
}

/* ====================== IGNORE REPORTS CONFIG ====================== */

void load_ignore_reports(void) {
    pthread_mutex_lock(&report_ignore_lock);
    ignored_reports_count = 0;

    FILE *file = fopen(ignore_file, "r");
    if (!file) {
        log_filtered(3, "No ignore.conf found at %s (normal)", ignore_file);
        pthread_mutex_unlock(&report_ignore_lock);
        return;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        char *trimmed = trim(line);

        if (strlen(trimmed) == 0 || trimmed[0] == '#')
            continue;

        if (ignored_reports_count >= MAX_IGNORED) {
            log_msg("Warning: maximum ignore reports (%d) reached", MAX_IGNORED);
            continue;
        }

        strncpy(ignored_reports[ignored_reports_count].exe, trimmed, PATH_MAX - 1);
        ignored_reports[ignored_reports_count].exe[PATH_MAX - 1] = '\0';
        ignored_reports_count++;
    }

    fclose(file);
    last_ignore_mtime = time(NULL);
    log_filtered(3, "Loaded %d entries to ignore reports from %s", ignored_reports_count, ignore_file);
    pthread_mutex_unlock(&report_ignore_lock);
}

int file_has_changed() {
    time_t current = get_config_max_mtime();
    if (current > last_config_mtime) {
        log_msg("Config file changed externally, reloading...");
        load_user_config();
        return 1;
    }
    return 0;
}

/* ====================== IGNORED CHECK ====================== */

int is_ignored(const char *exe, int action_id) {
    if (!exe || *exe == '\0' || strcmp(exe, "?") == 0) {
        pthread_mutex_unlock(&ignored_lock);
        return 0;
    }

    const char *action_name = action_to_string(action_id);
    if (!action_name || strcmp(action_name, "UNKNOWN") == 0)
        return 0;

    pthread_mutex_lock(&ignored_lock);
    for (int i = 0; i < ignored_count; i++) {
        if (!pattern_matches(exe, ignored_cmds[i].exe_pattern)) // barrieif (fnmatch(ignored_cmds[i].exe_pattern, exe, FNM_PATHNAME | FNM_NOESCAPE) != 0)
            continue;

        if (ignored_cmds[i].action[0] == '\0' || 
            strcasecmp(ignored_cmds[i].action, action_name) == 0) {
            pthread_mutex_unlock(&ignored_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&ignored_lock);
    return 0;
}

int is_report_ignored(const char *exe) {
    if (!exe || *exe == '\0' || strcmp(exe, "?") == 0)
        return 0;

    pthread_mutex_lock(&report_ignore_lock);
    for (int i = 0; i < ignored_reports_count; i++) {
        if (strcmp(ignored_reports[i].exe, exe) == 0) {
            pthread_mutex_unlock(&report_ignore_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&report_ignore_lock);
    return 0;
}

/* ====================== ZENITY DIALOG ====================== */

int show_zenity_dialog(const struct Alert *alert) { 
    char zenity_cmd[8192];
    const char *action_str = action_to_string(alert->action);
    const char *action_desc = action_to_description(alert->action);
    snprintf(zenity_cmd, sizeof(zenity_cmd),
        "zenity --question "
        "--title='XnsGuard' "
        "--icon-name=dialog-warning "
        "--modal "
        "--timeout=60 "
        "--text='<b>Permission:</b> %s (%s)\n"
                 "<b>Program:</b> %s' "
        "--ok-label='Allow' "
        "--cancel-label='Deny this session' "
        "--extra-button='Allow this session' "
        "--extra-button='Deny' "
        "--extra-button='Allow all actions' "
        "--width=550 "
        "--no-wrap 2>/dev/null",
        action_str, action_desc, trim_exe_for_log(alert->exe));

    log_msg("Showing Zenity dialog for %s %s (%d)",
            action_str, trim_exe_for_log(alert->exe), alert->pid);

    FILE *fp = popen(zenity_cmd, "r");
    if (!fp) {
        log_msg("ERROR: failed to call zenity");
        return 3;
    }

    char output[256] = {0};
    if (fgets(output, sizeof(output), fp) != NULL) {
        output[strcspn(output, "\n")] = '\0';
    }

    int status = pclose(fp);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    log_msg("Zenity returned %d | '%s'", code, output);

    if (code == 0) {
        return 0;
    } else if (strstr(output, "Allow this session") != NULL) {
        return 1;
    } else if (strstr(output, "Deny") != NULL) {
        return 2;
    } else if (strstr(output, "Allow all actions") != NULL) {
        return 3;
    } else {
        return 99;
    }
}


/* ====================== ALERT HANDLING ====================== */

void save_ignored_entry(const char *exe, int action_id) {
    if (!exe || *exe == '\0') return;

    const char *action_str = action_to_string(action_id);

    pthread_mutex_lock(&ignored_lock);

    for (int i = 0; i < ignored_count; i++) {
        if (strcmp(ignored_cmds[i].exe_pattern, exe) == 0 &&
            strcmp(ignored_cmds[i].action, action_str) == 0) {
            pthread_mutex_unlock(&ignored_lock);
            log_msg("Rule already exists: %s:%s", trim_exe_for_log(exe), action_str);
            return;
        }
    }
    pthread_mutex_unlock(&ignored_lock);

    FILE *file = fopen(perms_file, "a");
    if (!file) {
        return;
    }

    fprintf(file, "ALLOW %s %s\n", action_str, exe);
    fclose(file);
    load_user_config();
}

int is_seen(const char *exe, int action) {
    for (int i = 0; i < seen_count; i++) {
        if (strcmp(seen_alerts[i].exe, exe) == 0 && seen_alerts[i].action == action) {
            return 1;
        }
    }
    return 0;
}

void add_seen(const char *exe, int action) {
    if (seen_count < MAX_ALERTS) {
        strncpy(seen_alerts[seen_count].exe, exe, sizeof(seen_alerts[seen_count].exe)-1);
        seen_alerts[seen_count].action = action;
        seen_count++;
    }
}

void remove_seen_for_exe(const char *exe, int action) {
    int i = 0;
    while (i < seen_count) {
        if (strcmp(seen_alerts[i].exe, exe) == 0 && seen_alerts[i].action == action) {
            for (int j = i; j < seen_count - 1; j++) {
                seen_alerts[j] = seen_alerts[j + 1];
            }
            seen_count--;
        } else {
            i++;
        }
    }
}

void remove_all_alerts_for_pid(pid_t pid) {
    int i = 0;
    while (i < alert_count) {
        if (alert_queue[i].pid == pid) {
            for (int j = i; j < alert_count - 1; j++) {
                alert_queue[j] = alert_queue[j + 1];
            }
            alert_count--;
        } else {
            i++;
        }
    }
}

void send_query_action(const char *action) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *base_dir = (runtime_dir && *runtime_dir) ? runtime_dir : "/tmp";

    char socket_path[108];
    snprintf(socket_path, sizeof(socket_path), "%s/xperms.sock", base_dir);

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock == -1) return;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    char msg[256];
    snprintf(msg, sizeof(msg),
             "{\"command\":\"QUERY_ACTION\",\"action\":\"%s\"}", action);

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
}

void send_permission(int action, const char *exe, pid_t pid, int command_type) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *base_dir = (runtime_dir && *runtime_dir) ? runtime_dir : "/tmp";

    char socket_path[108];
    snprintf(socket_path, sizeof(socket_path), "%s/xperms.sock", base_dir);

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock == -1) {
        log_msg("Failed to create permission socket: %s", strerror(errno));
        return;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    char msg[256];
    const char *cmd_name = "ALLOW";

    switch (command_type) {
        case COMMAND_HEARTBEAT:  /* heartbeat */
            snprintf(msg, sizeof(msg), "{\"command\":\"XNOTIFY\",\"pid\":%d}", pid);
            cmd_name = "HEARTBEAT";
            break;
        case COMMAND_ALLOW_ALL:  /* ALLOW_ALL */
            snprintf(msg, sizeof(msg), "{\"command\":\"ALLOW_ALL\",\"exe\":\"%s\",\"action\":%d}", exe, action);
            cmd_name = "ALLOW_ALL";
            break;
        case COMMAND_ALLOW_ACTION:  /* ALLOW_ACTION */
            snprintf(msg, sizeof(msg), "{\"command\":\"ALLOW_ACTION\",\"action\":%d}", action);
            cmd_name = "ALLOW_ACTION";
            break;
        case COMMAND_DENY:  /* DENY */
            snprintf(msg, sizeof(msg), "{\"command\":\"DENY\",\"action\":%d,\"exe\":\"%s\"}", action, exe);
            cmd_name = "DENY";
            break;
        case COMMAND_DENY_ALL: /* DENY_ALL */
            snprintf(msg, sizeof(msg), "{\"command\":\"DENY_ALL\",\"exe\":\"%s\"}", exe);
            cmd_name = "DENY_ALL";
            break;
        case COMMAND_DENY_ACTION: /* DENY_ACTION */
            snprintf(msg, sizeof(msg), "{\"command\":\"DENY_ACTION\",\"action\":%d}", action);
            cmd_name = "DENY_ACTION";
            break;
        default: /* ALLOW */
            snprintf(msg, sizeof(msg), "{\"command\":\"ALLOW\",\"action\":%d,\"exe\":\"%s\"}", action, exe);
            cmd_name = "ALLOW";
            break;
    }

    ssize_t sent = sendto(sock, msg, strlen(msg), 0,
                          (struct sockaddr*)&addr, sizeof(addr));

    close(sock);

    if (sent == -1) {
        log_msg("Failed to send permission: %s", strerror(errno));
    } else if (command_type != 1) {
        log_filtered(2, "Sent: %s (%d) for %s", cmd_name, action, trim_exe_for_log(exe));
    }
}

void handle_message(const char *msg) {
    int action = 0;
    pid_t pid = 0;
    char exe[PATH_MAX] = "?";
    char command[64] = "?";

    char *p = strstr(msg, "\"command\":\"");
    if (p) {
        p += 11;
        char *end = strchr(p, '"');
        if (end) {
            strncpy(command, p, end - p);
            command[end - p] = '\0';
        }
    }

    p = strstr(msg, "\"action\":");
    if (p)
        sscanf(p + 9, "%d", &action);

    p = strstr(msg, "\"pid\":");
    if (p) 
        sscanf(p + 6, "%d", &pid);

    p = strstr(msg, "\"exe\":\"");
    if (p) {
        p += 7;
        char *end = strchr(p, '"');
        if (end) {
            strncpy(exe, p, end - p);
            exe[end - p] = '\0';
        }
    }

    if (exe[0] == '\0') {
        strcpy(exe, "?");
    }

    if (action <= 0 || pid <= 0) 
        return;

    const char *action_str = action_to_string(action);

    if (strcmp(command, "REPORT") == 0) {
        if (is_report_ignored(exe)) {
            // Silencioso - não loga nada
            return;
        }
        log_msg("REPORT: %s is using %s (%d)", trim_exe_for_log(exe), action_str, action);
        time_t now = time(NULL);
        if (strcmp(exe, last_report.exe) == 0 && action == last_report.action &&
            now - last_report.last_time < REPORT_THROTTLE_MS)
            return;

        strncpy(last_report.exe, exe, sizeof(last_report.exe)-1);
        last_report.action = action;
        last_report.last_time = now;
        return;
    }

    log_msg("X server requested %s for %s", action_str, trim_exe_for_log(exe));

    int pre = get_preconfig_rule(exe, action);
    
    if (pre == 1) {
        send_permission(action, exe, pid, COMMAND_ALLOW);
        return;
    }
    if (pre == 2) {
        send_permission(action, exe, pid, COMMAND_DENY);
        return;
    }
    
    if (is_seen(exe, action)) {
        log_filtered(3, "Duplicate request %s %s (%d) - ignoring", action_str, trim_exe_for_log(exe), pid);
        return;
    }

    int paused = 0;

    if (!no_pause_mode) {
        paused = (kill(pid, SIGSTOP) == 0);
        if (!paused && errno != ESRCH) {
            log_msg("Failed to pause PID %d: %s", pid, strerror(errno));
        }
    }

    add_seen(exe, action);

    pthread_mutex_lock(&queue_lock);
    if (alert_count < MAX_ALERTS) {
        alert_queue[alert_count].pid = pid;
        alert_queue[alert_count].action = action;
        strcpy(alert_queue[alert_count].exe, exe);
        strcpy(alert_queue[alert_count].time_str, get_current_time());
        alert_queue[alert_count].paused = paused;
        alert_count++;
        log_filtered(2, "Alert queued: %s : %s (%d pending)", trim_exe_for_log(exe), action_str, alert_count);
    } else {
        log_msg("Alert queue full! Dropping request for %s", trim_exe_for_log(exe));
    }
    pthread_mutex_unlock(&queue_lock);
}

void process_next_alert() {
    pthread_mutex_lock(&queue_lock);
    if (alert_count == 0) {
        pthread_mutex_unlock(&queue_lock);
        return;
    }

    struct Alert alert = alert_queue[0];

    for (int i = 0; i < alert_count - 1; i++) {
        alert_queue[i] = alert_queue[i + 1];
    }
    alert_count--;
    pthread_mutex_unlock(&queue_lock);

    int response = -1;

    pthread_mutex_unlock(&queue_lock);

    response = show_zenity_dialog(&alert);

    pthread_mutex_lock(&queue_lock);
    
    if (always_kill_mode) {
        log_msg("ALWAYS-KILL mode active → killing PID %d (%s)", alert.pid, alert.exe);
        response = 1;
    }

    if (quiet_mode) {
        log_msg("QUIET mode: default action is DENY THIS SESSION for %s (PID %d)", trim_exe_for_log(alert.exe), alert.pid);
        response = 2;
    }

    if (response == 0) {
        log_filtered(1, "ALLOWED: %s : %s", trim_exe_for_log(alert.exe), action_to_string(alert.action));
        save_rule(alert.exe, alert.action, 1);
        send_permission(alert.action, alert.exe, alert.pid, COMMAND_ALLOW);
    } else if (response == 1) {
        log_filtered(1, "ALLOWED THIS SESSION: %s : %s", trim_exe_for_log(alert.exe), action_to_string(alert.action));
        send_permission(alert.action, alert.exe, alert.pid, COMMAND_ALLOW);
    } else if (response == 2) {
        log_filtered(1, "DENIED: %s : %s", trim_exe_for_log(alert.exe), action_to_string(alert.action));
        save_denied_entry(alert.exe, alert.action);
        send_permission(alert.action, alert.exe, alert.pid, COMMAND_DENY);
    } else if (response == 3) {
        log_filtered(1, "ALL ALLOWED: %s", trim_exe_for_log(alert.exe));
        save_rule(alert.exe, -1, -1);
        send_permission(alert.action, alert.exe, alert.pid, COMMAND_ALLOW_ALL);
    } else { 
        log_filtered(1, "DENIED THIS SESSION: %s : %s", trim_exe_for_log(alert.exe), action_to_string(alert.action));
        send_permission(alert.action, alert.exe, alert.pid, COMMAND_DENY);
    }

    if (alert.paused && !no_pause_mode)
        kill(alert.pid, SIGCONT);

    remove_seen_for_exe(alert.exe, alert.action);

    if (kill(alert.pid, 0) != 0 && errno == ESRCH) {
        log_filtered(2, "PID %d no longer exists, discarding alert", alert.pid);
        remove_all_alerts_for_pid(alert.pid);
    }

    pthread_mutex_unlock(&queue_lock);
}

/* ====================== HEARTBEAT ====================== */

void send_heartbeat() {
    send_permission(0, "", getpid(), COMMAND_HEARTBEAT);
}

/* ====================== THREADS ====================== */

void* alert_processor_loop(void *arg) {
    (void)arg;
    while (!should_exit) {
        if (alert_count > 0)
            process_next_alert();
        usleep(150000);
    }
    return NULL;
}

void* file_monitor_loop(void *arg) {
    (void)arg;
    log_msg("File monitor thread started");
    while (!should_exit) {
        file_has_changed();
        sleep(1);
    }
    return NULL;
}

/* ====================== LOCK & CLEANUP ====================== */

int acquire_lock() {
    lock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lock_fd < 0) {
        log_msg("Failed to create lock socket: %s", strerror(errno));
        return 0;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LOCK_SOCKET_PATH_BUF, sizeof(addr.sun_path) - 1);
    
    unlink(LOCK_SOCKET_PATH_BUF);

    if (bind(lock_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        if (errno == EADDRINUSE)
            log_msg("XnsGuard is already running. Exiting.");
        else
            log_msg("Failed to bind lock socket: %s", strerror(errno));
        close(lock_fd);
        return 0;
    }
    
    chmod(LOCK_SOCKET_PATH_BUF, 0666);
    listen(lock_fd, 1);
    return 1;
}

void release_lock() {
    if (lock_fd >= 0) {
        close(lock_fd);
        unlink(LOCK_SOCKET_PATH_BUF);
    }
}

void cleanup(int sig) {
    log_msg("Shutting down (signal %d)...", sig);
    should_exit = 1;
    
    pthread_join(file_monitor_thread, NULL);
    pthread_join(processor_thread, NULL);
    
    if (server_fd >= 0) {
        close(server_fd);
        unlink(SOCKET_PATH_BUF);
    }
    
    release_lock();
    exit(0);
}

/* ====================== MAIN ====================== */

int main(int argc, char *argv[]) {
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-pause") == 0 ||
            strcmp(argv[i], "--notify-only") == 0) {
            no_pause_mode = 1;
            log_msg("NOTIFY-ONLY mode activated (no process pausing)");
        } else if (strcmp(argv[i], "--quiet") == 0 ||
                 strcmp(argv[i], "--no-zenity") == 0) {
            quiet_mode = 1;
            log_msg("QUIET mode activated (no Zenity dialogs)");
        } else if (strcmp(argv[i], "--always-kill") == 0) {
            always_kill_mode = 1;
            log_msg("ALWAYS-KILL mode activated (unknown processes will be killed)");
        } else if (strncmp(argv[i], "--conf=", 7) == 0) {
            strncpy(config_dir, argv[i] + 7, sizeof(config_dir) - 1);
            config_dir[sizeof(config_dir)-1] = '\0';
        } else if (strcmp(argv[i], "--conf") == 0 && i + 1 < argc) {
            strncpy(config_dir, argv[i + 1], sizeof(config_dir) - 1);
            config_dir[sizeof(config_dir)-1] = '\0';
            i++;
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            int lvl = atoi(argv[i+1]);
            if (lvl >= 0 && lvl <= 4) log_level = lvl;
            i++;
        } else if (strncmp(argv[i], "--log-level=", 12) == 0) {
            int lvl = atoi(argv[i] + 12);
            if (lvl >= 0 && lvl <= 4) log_level = lvl;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --no-pause / --notify-only     Do not send SIGSTOP/SIGCONT\n");
            printf("  --quiet / --no-zenity          No Zenity dialogs, logs only\n");
            printf("  --always-kill                  Kill unknown processes immediately\n");
            printf("  --conf <dir> or --conf=<dir>   Base config directory (default: ~/.config/xnsguard)\n");
            printf("  --log-level N                  Verbosity level (0-4)\n");
            printf("  --help / -h                    Show this help\n");
            return 0;
        }
    }

    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *base_dir = (runtime_dir && *runtime_dir) ? runtime_dir : "/tmp";
    snprintf(SOCKET_PATH_BUF, sizeof(SOCKET_PATH_BUF), "%s/xnotify.sock", base_dir);
    snprintf(LOCK_SOCKET_PATH_BUF, sizeof(LOCK_SOCKET_PATH_BUF), "%s/xnotify.lock.sock", base_dir);

    if (config_dir[0] == '\0') {
        const char *home = getenv("HOME");
        if (home && *home) {
            snprintf(config_dir, sizeof(config_dir), "%s/.config/xnsguard", home);
        } else {
            strcpy(config_dir, "/tmp/xnsguard");
        }
    }

    snprintf(perms_file, sizeof(perms_file), "%s/perms.conf", config_dir);
    snprintf(ignore_file, sizeof(ignore_file), "%s/ignore.conf", config_dir);
    mkdir(config_dir, 0755);

    log_msg("XnsGuard starting - user config: %s", perms_file);

    if (!acquire_lock())
        return 1;

    load_user_config();
    load_ignore_reports();
    send_all_permissions_to_xserver();
    send_heartbeat();

    /* === Server socket setup === */
    server_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (server_fd == -1) {
        log_msg("Failed to create server socket: %s", strerror(errno));
        release_lock();
        return 1;
    }

    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH_BUF, sizeof(addr.sun_path) - 1);

    unlink(SOCKET_PATH_BUF);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_msg("Failed to bind server socket: %s", strerror(errno));
        close(server_fd);
        release_lock();
        return 1;
    }

    chmod(SOCKET_PATH_BUF, 0666);

    int rcvbuf = 4 * 1024 * 1024;  // 4 MB
    setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    log_msg("XnsGuard ready - listening on %s", SOCKET_PATH_BUF);

    pthread_create(&file_monitor_thread, NULL, file_monitor_loop, NULL);
    pthread_create(&processor_thread, NULL, alert_processor_loop, NULL);

    /* Main loop */
    struct pollfd pfd = {
        .fd = server_fd,
        .events = POLLIN,
    };

    while (!should_exit) {
        static time_t last_hb = 0;
        if (time(NULL) - last_hb >= 2) {
            send_heartbeat();
            last_hb = time(NULL);
        }

        int r = poll(&pfd, 1, 400);
        if (r > 0 && (pfd.revents & POLLIN)) {
            char buffer[BUF_SIZE] = {0};
            ssize_t n = recv(server_fd, buffer, sizeof(buffer)-1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                handle_message(buffer);
            }
        }
    }

    cleanup(0);
    return 0;
}