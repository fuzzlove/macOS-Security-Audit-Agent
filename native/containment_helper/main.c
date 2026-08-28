#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <xpc/xpc.h>
#include "message_identity.h"

#define HELPER_ID "com.fuzzlove.MacAuditAgent.ContainmentHelper"
#define MACH_SERVICE "com.fuzzlove.MacAuditAgent.ContainmentHelper.xpc"
#define PROTOCOL_VERSION "1.0"

#ifndef MSAA_EXPECTED_ENGINE_REQUIREMENT
#define MSAA_EXPECTED_ENGINE_REQUIREMENT ""
#endif

static void send_status(xpc_session_t peer) {
    xpc_object_t reply=xpc_dictionary_create(NULL,NULL,0);
    xpc_dictionary_set_string(reply,"protocol_version",PROTOCOL_VERSION);
    xpc_dictionary_set_string(reply,"helper_id",HELPER_ID);
    xpc_dictionary_set_bool(reply,"production_actions_enabled",false);
    xpc_dictionary_set_string(reply,"state","BLOCKED_CREDENTIALS");
    bool sent=xpc_session_send_message(peer,reply); (void)sent; xpc_release(reply);
}

static void accept_peer(xpc_session_t peer) {
    xpc_session_set_incoming_message_handler(peer, ^(xpc_object_t message) {
        if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
        if (!msaa_validate_xpc_message_sender(message,MSAA_EXPECTED_ENGINE_REQUIREMENT)) return;
        const char *operation=xpc_dictionary_get_string(message,"operation");
        if (operation != NULL && strcmp(operation,"status")==0) send_status(peer);
        /* No production action is accepted until the signed identity registry,
           journal and guardian are integrated into this executable. */
    });
    xpc_session_set_cancel_handler(peer, ^(xpc_rich_error_t error) { (void)error; });
    xpc_rich_error_t error=NULL;
    if (!xpc_session_activate(peer,&error)) xpc_listener_reject_peer(peer,"activation failed");
}

int main(int argc,char **argv) {
    if (argc==2 && strcmp(argv[1],"--self-check")==0) {
        printf("{\"helper_id\":\"%s\",\"mach_service\":\"%s\",\"protocol_version\":\"%s\",\"native\":true,\"production_actions_enabled\":false}\n",HELPER_ID,MACH_SERVICE,PROTOCOL_VERSION);
        return 0;
    }
    if (MSAA_EXPECTED_ENGINE_REQUIREMENT[0]=='\0') {
        fprintf(stderr,"AR-CNT-002: production engine code requirement is not compiled in\n"); return 2;
    }
    xpc_rich_error_t error=NULL;
    xpc_listener_t listener=xpc_listener_create(MACH_SERVICE,dispatch_get_main_queue(),XPC_LISTENER_CREATE_INACTIVE,^(xpc_session_t peer){ accept_peer(peer); },&error);
    if (listener==NULL) { fprintf(stderr,"AR-CNT-003: listener creation failed\n"); return 3; }
    if (xpc_listener_set_peer_code_signing_requirement(listener,MSAA_EXPECTED_ENGINE_REQUIREMENT)!=0) { fprintf(stderr,"AR-CNT-004: peer requirement invalid\n"); return 4; }
    if (!xpc_listener_activate(listener,&error)) { fprintf(stderr,"AR-CNT-003: listener activation failed\n"); return 3; }
    dispatch_main();
}
