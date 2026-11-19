/**
 * This package is forked from
 * https://github.com/cyberphone/json-canonicalization/tree/master/java/canonicalizer.
 *
 * <p>The reason for the fork is to deal with the fact TUF isn't canonicalizing to the spec but
 * rather to OLPC. <a href="https://sigstore.slack.com/archives/C03SZ6SHU90/p1666954634567219">Slack
 * thread</a> and <a href="https://github.com/theupdateframework/python-tuf/issues/457">related
 * issue</a>.
 *
 * <p>Our fork makes two small edits to {@link
 * dev.sigstore.tuf.json.canonicalizer.JsonCanonicalizer}: passing newline characters through
 * unescaped, and enforcing a maximum JSON nesting depth in {@code JsonDecoder} to guard against
 * stack overflow on untrusted inputs.
 */
package dev.sigstore.tuf.json.canonicalizer;
