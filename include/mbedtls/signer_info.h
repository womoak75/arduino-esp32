#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <assert.h>

#ifndef _H_SIGNER_INFO
#define _H_SIGNER_INFO
/**
 * \name Structures and functions for parsing and writing X.509 certificates
 *
 *
 * As used for S/MIME, RFC3161 and various others
 *
 *   See: RFC 5652 - Cryptographic Message Syntax (CMS) 
 *
 *   SignerInfo ::= SEQUENCE {
 *      version CMSVersion,
 *      sid SignerIdentifier,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *      signatureAlgorithm SignatureAlgorithmIdentifier,
 *      signature SignatureValue,
 *      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 *
 *    SignerIdentifier ::= CHOICE {
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 *    SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *    UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *    Attribute ::= SEQUENCE {
 *      attrType OBJECT IDENTIFIER,
 *      attrValues SET OF AttributeValue }
 *
 *    IssuerAndSerialNumber ::= SEQUENCE {
 *      issuer Name,
 *      serialNumber CertificateSerialNumber }
 *
 *    AttributeValue ::= ANY
 *
 *    SignatureValue ::= OCTET STRING
 */

/**
 * \name Container for a RFC 5262 SignerInfo structure.
 */

typedef struct mbedtls_asn1_ts_pki_signer_info {

  /** information on who placed the signature */

  mbedtls_x509_name sid_name;                   /**< Signer Identifier (sid) */
  mbedtls_asn1_bitstring sid_serial;            /**< issuerAndSerialNumber */

  /** signature digest that is signed -- SignatureValue */
  mbedtls_md_type_t sig_digest_type;            /**< DigestAlgorithmIdentifier (e.g SHA256) */
  unsigned char * sig_digest;                   /**< The digest that was signed */
  size_t sig_digest_len;                        /**< Digest length */

  /** The signature -- SignatureValue */
  mbedtls_pk_type_t sig_type;                   /**< SignatureAlgorithmIdentifier */
  unsigned char * sig;                          /**< The SignatureValue */
  size_t sig_len;                               /**< Length of the SignatureValue */

  /** The section of the DER that was signed */
  unsigned char * signed_attribute_raw;         /**< Pointer to the start of the signed section. */
  size_t signed_attribute_len;                  /**< Length of the signed section. */

  /** Information on the certificate used to sign. */
  mbedtls_md_type_t signing_cert_hash_type;     /**< Signing certifcate; hash algorithm */
  unsigned char * signing_cert_hash;            /**< The hash of the signing certificate. */
  size_t signing_cert_hash_len;                 /**< Length of the hash of the signing certificate. */
  
} mbedtls_asn1_ts_pki_signer_info;

/**
 * \brief               Retrieve the RFC5262 SignerInfo from a DER blob; and return a
 *                      populated mbedtls_asn1_ts_pki_signer_info structure on.
 *     
 *                      Updates the pointer to immediately behind the sequence.
 *
 * \param p             On entry, \c *p points to the start of the ASN.1 SignerInfo
 *                      sequence. 
 *                      On successful completion, \c *p points to the first byte
 *                      beyond this sequence.
 *                      On error, the value of \c *p is undefined.
 * \param end           End of data.
 * \param signer_info   On success, the parsed data.
 *
 * \return      0 if successful.
 * \return      An ASN.1 error code if there is a malformed tag.
 * \return      #MBEDTLS_ERR_ASN1_INVALID_LENGTH if the stucture is incomplete
 *              #MBEDTLS_ERR_ASN1_INVALID_DATA is returned if the DER could
 *              not be parsed.
 *              
 */
int mbedtls_ts_get_signer_info(unsigned char **p, unsigned char * end, mbedtls_asn1_ts_pki_signer_info * signer_info);
#endif
