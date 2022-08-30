/**
 * Classes used for SCT verification.
 *
 * <p>This code is originally from the Conscrypt project (https://github.com/google/conscrypt)
 *
 * <p>The code was forked to remove architecture native dependencies. Those code paths were
 * reimplemented in Java (using bouncy castle primitives).
 *
 * <p>We also remove the code that deals with OSCP and TLS modes for SCTs certs because we don't
 * care about or use those.
 *
 * @see <a
 *     href="https://github.com/google/conscrypt/tree/86ff4e3fd4b6b3bb76a7ec0e91290384401ccbf3/common/src/main/java/org/conscrypt/ct">
 *     certificate transparency directory at commit 86ff4e3fd4b6b3bb76a7ec0e91290384401ccbf3</a>
 */
package dev.sigstore.encryption.certificates.transparency;
