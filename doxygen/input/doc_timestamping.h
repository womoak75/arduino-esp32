/**
 * \file doc_timestamping.h
 *
 * \brief RFC3161 Timestamping module documentation file.
 * 
 */
/*
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/** \defgroup ts_module RFC3161 timestamping module
 * 
 * Routines for RFC3161 signature validation of files and
 * their timestamps (e.g. for configuration and firmware updates).
 */

/**
 * @addtogroup ts_module RFC3161 timestamping module
 *
 * The RFC3161 timestamping module provides support for X.509 signed
 * digests (of files) and signed timestamps.
 * 
 * In summary:
 * - Decode a DER signature into a  \c mbedtls_ts_reply (see \c mbedtls_ts_reply_parse_der())
 * - Verify a DER signature against a Trustchain and the message signed (see \c  mbedtls_ts_verify_payload_with_der())
 *
 * And the conveniece calls:
 *
 * - Verify a \c mbedtls_ts_reply against a Trustchain (see \c  mbedtls_ts_verify())
 * - Verify a \c mbedtls_ts_reply against a Trustchain and the digest of the payload (see \c mbedtls_ts_verify_digest())
 * - Verify a \c mbedtls_ts_reply against a Trustchain and the message signed (see \c  mbedtls_ts_verify_payload())
 *
 * The \c mbedtls_ts_reply can then be examined for things such as \ref mbedtls_ts_reply.ts_info its \ref mbedtls_asn1_ts_pki_signer_info.signed_time (when was it signed), everything
 * about the signer (\ref mbedtls_ts_reply.ts_info its \ref mbedtls_asn1_ts_pki_signer_info.signer_info) and so on.
 *
 * This module can be used to validate that a file is signed by a party
 * trusted by X.509 infrastructure configured; and that it was signed
 * on, before or after some specific date.
 *
 * This is useful for things such as configuration files and updates.
 *
 */
