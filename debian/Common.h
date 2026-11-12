/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#ifndef PIE_PAM_COMMON_H
#define PIE_PAM_COMMON_H

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
#include <security/pam_modules.h>

#define CFReleaseSafe(x) do { CFTypeRef pie_ref_ = (x); if (pie_ref_ != NULL) CFRelease(pie_ref_); } while (0)

int od_record_create_cstring(pam_handle_t *, ODRecordRef *, const char *);
int od_record_check_pwpolicy(ODRecordRef, CFErrorRef *);
int od_record_check_authauthority(ODRecordRef);
int od_record_check_homedir(ODRecordRef);
int od_record_check_shell(ODRecordRef);

#endif
