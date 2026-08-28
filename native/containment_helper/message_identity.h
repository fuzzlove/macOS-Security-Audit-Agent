#ifndef MSAA_MESSAGE_IDENTITY_H
#define MSAA_MESSAGE_IDENTITY_H
#include <stdbool.h>
#include <xpc/xpc.h>
bool msaa_validate_xpc_message_sender(xpc_object_t message,const char *requirement);
#endif
