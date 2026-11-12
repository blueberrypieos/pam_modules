/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#include <DirectoryService/DirServicesTypes.h>
#include <DirectoryService/DirServicesConst.h>
#include <security/pam_modules.h>
#include <security/openpam.h>

#include "Common.h"
#include "Logging.h"

int
od_record_create_cstring(pam_handle_t *handle, ODRecordRef *found, const char *login)
{
	const void *wanted[] = {
		kODAttributeTypeAuthenticationAuthority,
		kODAttributeTypeNFSHomeDirectory,
		kODAttributeTypeUserShell,
	};
	CFStringRef name = NULL;
	CFArrayRef attributes = NULL;
	ODNodeRef node = NULL;
	CFErrorRef error = NULL;
	int result = PAM_BUF_ERR;

	(void)handle;
	if (found == NULL || login == NULL)
		return PAM_SERVICE_ERR;
	*found = NULL;

	name = CFStringCreateWithCString(NULL, login, kCFStringEncodingUTF8);
	attributes = CFArrayCreate(NULL, wanted, sizeof(wanted) / sizeof(wanted[0]),
	    &kCFTypeArrayCallBacks);
	if (name == NULL || attributes == NULL)
		goto out;

	node = ODNodeCreateWithNodeType(NULL, kODSessionDefault, eDSAuthenticationSearchNodeName, &error);
	if (node == NULL) {
		_LOG_ERROR("cannot open the authentication search node");
		result = PAM_SERVICE_ERR;
		goto out;
	}

	*found = ODNodeCopyRecord(node, kODRecordTypeUsers, name, attributes, &error);
	result = *found != NULL ? PAM_SUCCESS : PAM_USER_UNKNOWN;
	if (result != PAM_SUCCESS)
		_LOG_DEBUG("no user record for %s", login);

out:
	CFReleaseSafe(error);
	CFReleaseSafe(node);
	CFReleaseSafe(attributes);
	CFReleaseSafe(name);
	return result;
}

int
od_record_check_pwpolicy(ODRecordRef record, CFErrorRef *errorp)
{
	CFErrorRef error = NULL;
	int result = PAM_SUCCESS;

	if (record == NULL)
		return PAM_SERVICE_ERR;

	if (!ODRecordAuthenticationAllowed(record, &error)) {
		switch (error != NULL ? CFErrorGetCode(error) : 0) {
		case kODErrorCredentialsAccountNotFound:
			result = PAM_USER_UNKNOWN;
			break;
		case kODErrorCredentialsAccountDisabled:
		case kODErrorCredentialsAccountInactive:
			result = PAM_PERM_DENIED;
			break;
		case kODErrorCredentialsPasswordExpired:
		case kODErrorCredentialsPasswordChangeRequired:
			result = PAM_NEW_AUTHTOK_REQD;
			break;
		case kODErrorCredentialsAccountTemporarilyLocked:
			result = PAM_APPLE_ACCT_TEMP_LOCK;
			break;
		case kODErrorCredentialsAccountLocked:
			result = PAM_APPLE_ACCT_LOCKED;
			break;
		default:
			result = PAM_AUTH_ERR;
			break;
		}
	}

	if (errorp != NULL)
		*errorp = error;
	else
		CFReleaseSafe(error);
	return result;
}

static int
first_value(ODRecordRef record, ODAttributeType attribute, CFStringRef *value)
{
	CFArrayRef values;
	CFTypeRef first;

	*value = NULL;
	if (record == NULL)
		return PAM_SERVICE_ERR;

	values = ODRecordCopyValues(record, attribute, NULL);
	if (values == NULL)
		return PAM_SUCCESS;
	if (CFArrayGetCount(values) > 0) {
		first = CFArrayGetValueAtIndex(values, 0);
		if (CFGetTypeID(first) != CFStringGetTypeID()) {
			CFRelease(values);
			return PAM_PERM_DENIED;
		}
		*value = CFRetain(first);
	}
	CFRelease(values);
	return PAM_SUCCESS;
}

static int
check_value(ODRecordRef record, ODAttributeType attribute, bool (*refused)(CFStringRef))
{
	CFStringRef value;
	int result;

	result = first_value(record, attribute, &value);
	if (result == PAM_SUCCESS && value != NULL && refused(value))
		result = PAM_PERM_DENIED;
	CFReleaseSafe(value);
	if (result != PAM_SUCCESS)
		_LOG_ERROR("account refused: %d", result);
	return result;
}

static bool
disabled_authority(CFStringRef value)
{
	return CFStringHasPrefix(value, CFSTR(kDSValueAuthAuthorityDisabledUser));
}

static bool
no_home(CFStringRef value)
{
	return CFEqual(value, CFSTR("/dev/null")) || CFEqual(value, CFSTR("99"));
}

static bool
false_shell(CFStringRef value)
{
	return CFEqual(value, CFSTR("/usr/bin/false"));
}

int
od_record_check_authauthority(ODRecordRef record)
{
	return check_value(record, kODAttributeTypeAuthenticationAuthority, disabled_authority);
}

int
od_record_check_homedir(ODRecordRef record)
{
	return check_value(record, kODAttributeTypeNFSHomeDirectory, no_home);
}

int
od_record_check_shell(ODRecordRef record)
{
	return check_value(record, kODAttributeTypeUserShell, false_shell);
}
