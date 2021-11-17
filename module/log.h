#ifndef _LOG_H
#define _LOG_H

#include "fw.h"

int is_log_row_matching(log_row_t *log_row, packet_t *packet, reason_t packet_reason, __u8 packet_action);
void log_packet(log_t *log, packet_t *packet, reason_t reason, __u8 action);
void resize_log(log_t *log, int resizing_factor);
void clear_log(log_t *log);

#endif // _LOG_H_
