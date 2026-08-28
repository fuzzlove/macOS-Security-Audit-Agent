#import "ipc_peer_auth.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

static bool equal_utf8(CFTypeRef value, const char *expected) {
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID() || expected == NULL) return false;
    return [(__bridge NSString *)value isEqualToString:[NSString stringWithUTF8String:expected]];
}

msaa_ar_peer_auth_result_t msaa_ar_authenticate_audit_token(
    audit_token_t token,
    const char *expected_team_id,
    const char *expected_signing_id,
    const char *designated_requirement,
    bool production_mode
) {
    if (expected_team_id == NULL || expected_signing_id == NULL || designated_requirement == NULL) {
        return MSAA_AR_PEER_AUTH_INVALID_ARGUMENT;
    }
    NSData *token_data = [NSData dataWithBytes:&token length:sizeof(token)];
    NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributeAudit: token_data};
    SecCodeRef code = NULL;
    if (SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code) != errSecSuccess || code == NULL) {
        return MSAA_AR_PEER_AUTH_CODE_LOOKUP_FAILED;
    }
    msaa_ar_peer_auth_result_t result = MSAA_AR_PEER_AUTH_SIGNATURE_INVALID;
    SecRequirementRef requirement = NULL;
    CFStringRef requirement_text = CFStringCreateWithCString(kCFAllocatorDefault, designated_requirement, kCFStringEncodingUTF8);
    if (requirement_text == NULL || SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags, &requirement) != errSecSuccess) {
        result = MSAA_AR_PEER_AUTH_REQUIREMENT_INVALID;
        goto cleanup;
    }
    if (SecCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement) != errSecSuccess) {
        result = MSAA_AR_PEER_AUTH_SIGNATURE_INVALID;
        goto cleanup;
    }
    CFDictionaryRef signing = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing) != errSecSuccess || signing == NULL) {
        goto cleanup;
    }
    if (!equal_utf8(CFDictionaryGetValue(signing, kSecCodeInfoTeamIdentifier), expected_team_id)) {
        result = MSAA_AR_PEER_AUTH_TEAM_MISMATCH;
    } else if (!equal_utf8(CFDictionaryGetValue(signing, kSecCodeInfoIdentifier), expected_signing_id)) {
        result = MSAA_AR_PEER_AUTH_IDENTIFIER_MISMATCH;
    } else {
        uint32_t flags = 0;
        CFNumberRef number = (CFNumberRef)CFDictionaryGetValue(signing, kSecCodeInfoFlags);
        if (number != NULL) CFNumberGetValue(number, kCFNumberSInt32Type, &flags);
        result = production_mode && (flags & kSecCodeSignatureAdhoc) != 0 ? MSAA_AR_PEER_AUTH_AD_HOC_REJECTED : MSAA_AR_PEER_AUTH_OK;
    }
    CFRelease(signing);

cleanup:
    if (requirement != NULL) CFRelease(requirement);
    if (requirement_text != NULL) CFRelease(requirement_text);
    CFRelease(code);
    return result;
}
