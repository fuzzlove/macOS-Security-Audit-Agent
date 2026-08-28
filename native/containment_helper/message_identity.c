#include "message_identity.h"
#include <Security/Security.h>

bool msaa_validate_xpc_message_sender(xpc_object_t message,const char *requirement_text) {
    if (message==NULL || xpc_get_type(message)!=XPC_TYPE_DICTIONARY || requirement_text==NULL || requirement_text[0]=='\0') return false;
    SecCodeRef sender=NULL; SecRequirementRef requirement=NULL;
    CFStringRef text=CFStringCreateWithCString(kCFAllocatorDefault,requirement_text,kCFStringEncodingUTF8);
    if (text==NULL) return false;
    OSStatus status=SecCodeCreateWithXPCMessage(message,kSecCSDefaultFlags,&sender);
    if (status==errSecSuccess) status=SecRequirementCreateWithString(text,kSecCSDefaultFlags,&requirement);
    if (status==errSecSuccess) status=SecCodeCheckValidity(sender,kSecCSStrictValidate|kSecCSCheckAllArchitectures,requirement);
    if (requirement) CFRelease(requirement);
    if (sender) CFRelease(sender);
    CFRelease(text);
    return status==errSecSuccess;
}
