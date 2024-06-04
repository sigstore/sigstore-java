/*
 * Copyright 2022 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.sigstore.testing;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A certificate generator, useful when trying to talk to rekor without actually using fulcio/oidc.
 */
public class CertGenerator {
  public static Certificate newCert(PublicKey publicKey)
      throws OperatorCreationException, CertificateException, IOException,
          NoSuchAlgorithmException {

    // generate a keypair for signing this certificate
    KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("EC");
    keypairGen.initialize(256);
    KeyPair certSigningKeyPair = keypairGen.generateKeyPair();

    // create the cert test subject
    X500Name subject =
        new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "test")
            .addRDN(BCStyle.O, "test certificate")
            .build();

    // create a short lived cert
    Date startDate = new Date(System.currentTimeMillis());
    var calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.ROOT);
    calendar.setTime(startDate);
    calendar.add(Calendar.MINUTE, 20);
    var endDate = calendar.getTime();

    // arbitrary serial number
    BigInteger serial = new BigInteger(Long.toString(System.currentTimeMillis()));

    X509v3CertificateBuilder certificate =
        new JcaX509v3CertificateBuilder(subject, serial, startDate, endDate, subject, publicKey);

    // add all extensions like a real fulcio cert
    var keyIdgen = new JcaX509ExtensionUtils();
    certificate.addExtension(
        Extension.subjectKeyIdentifier, false, keyIdgen.createSubjectKeyIdentifier(publicKey));
    certificate.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        keyIdgen.createAuthorityKeyIdentifier(certSigningKeyPair.getPublic())); // this is nonsense
    certificate.addExtension(
        Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded());
    certificate.addExtension(
        Extension.extendedKeyUsage,
        false,
        new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).getEncoded());
    certificate.addExtension(
        Extension.basicConstraints, true, new BasicConstraints(false).getEncoded());
    certificate.addExtension(
        Extension.subjectAlternativeName,
        true,
        new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.com")).getEncoded());
    // identity provider
    certificate.addExtension(
        new ASN1ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
        false,
        "https://fakeaccounts.test.com".getBytes(StandardCharsets.UTF_8));
    certificate.addExtension(
        new ASN1ObjectIdentifier("1.3.6.1.4.1.57264.1.8"),
        false,
        new DERUTF8String("https://fakeaccounts.test.com").getEncoded());
    certificate.addExtension(
        new ASN1ObjectIdentifier(("1.3.6.1.4.1.99999.42.42")),
        false,
        "test value".getBytes(StandardCharsets.UTF_8));
    certificate.addExtension(
        new ASN1ObjectIdentifier(("1.3.6.1.4.1.99999.42.43")),
        false,
        new DERUTF8String("test value der").getEncoded());

    // sign cert
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").build(certSigningKeyPair.getPrivate());
    X509CertificateHolder holder = certificate.build(signer);

    // covert cert to a Java native x509 cert
    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    converter.setProvider(new BouncyCastleProvider());

    return converter.getCertificate(holder);
  }
}
