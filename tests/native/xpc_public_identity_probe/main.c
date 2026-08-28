#include <Security/SecCode.h>
#include <stdio.h>
#include <xpc/xpc.h>
int main(void) {
    OSStatus (*public_api)(xpc_object_t,SecCSFlags,SecCodeRef *)=SecCodeCreateWithXPCMessage;
    printf("{\"SecCodeCreateWithXPCMessage\":%s,\"raw_audit_token_api_used\":false}\n",public_api?"true":"false");
    return public_api?0:1;
}
