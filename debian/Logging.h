/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#define PIE_LOG(level, ...) openpam_log(PAM_LOG_##level, __VA_ARGS__)
#define _LOG_DEBUG(...) PIE_LOG(DEBUG, __VA_ARGS__)
#define _LOG_VERBOSE(...) PIE_LOG(VERBOSE, __VA_ARGS__)
#define _LOG_INFO(...) PIE_LOG(VERBOSE, __VA_ARGS__)
#define _LOG_DEFAULT(...) PIE_LOG(NOTICE, __VA_ARGS__)
#define _LOG_ERROR(...) PIE_LOG(ERROR, __VA_ARGS__)
