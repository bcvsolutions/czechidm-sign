package eu.bcvsolutions.idm.sign.service.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import eu.bcvsolutions.idm.core.api.service.ConfigurationService;
import eu.bcvsolutions.idm.core.security.api.domain.GuardedString;
import eu.bcvsolutions.idm.sign.config.domain.SignConfiguration;
import eu.bcvsolutions.idm.sign.service.api.SignSignatureService;
import eu.bcvsolutions.idm.test.api.AbstractIntegrationTest;

public class DefaultSignSignatureServiceTest extends AbstractIntegrationTest {

	public static boolean initRan = false;
	private String testKeystorePass = "keystorePass";
	private String testKeystoreLocation = "src/test/resources/keystore.jks";
	private KeyStore ks;
	private String privatePass = "pass12";
	private String privatePass1 = "pass1234";
	private String privatePass2 = "pass123456";
	private String aliasPrivate = "private key";
	private String aliasPrivate1 = "private key1";
	private String aliasPrivate2 = "private key2";

	@Autowired
	private SignSignatureService signSignatureService;
	@Autowired
	private ConfigurationService configurationService;

	@Before
	public void init() throws GeneralSecurityException, IOException, OperatorCreationException {
		if (!initRan) {
			ks = KeyStore.getInstance("JKS");
			ks.load(null, testKeystorePass.toCharArray());
			try (FileOutputStream fos = new FileOutputStream(testKeystoreLocation)) {
				ks.store(fos, testKeystorePass.toCharArray());
			}

			configurationService.setValue(SignConfiguration.KEYSTORE_LOCATION, testKeystoreLocation);
			configurationService.setValue(SignConfiguration.KEYSTORE_PASSWORD, testKeystorePass);

			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(3072);
			KeyPair keyPair = keyGenerator.generateKeyPair();
			KeyPair keyPair1 = keyGenerator.generateKeyPair();
			KeyPair keyPair2 = keyGenerator.generateKeyPair();

			Certificate[] chain = {generate(keyPair, "SHA256withRSA", "one", 1825)};
			Certificate[] chain1 = {generate(keyPair1, "SHA256withRSA", "two", 1825)};
			Certificate[] chain2 = {generate(keyPair2, "SHA256withRSA", "three", 1825)};

			ks.setKeyEntry(aliasPrivate, keyPair.getPrivate(), privatePass.toCharArray(), chain);
			ks.setKeyEntry(aliasPrivate1, keyPair1.getPrivate(), privatePass1.toCharArray(), chain1);
			ks.setKeyEntry(aliasPrivate2, keyPair2.getPrivate(), privatePass2.toCharArray(), chain2);

			//Storing the KeyStore object
			try (FileOutputStream fos = new FileOutputStream(testKeystoreLocation)) {
				ks.store(fos, testKeystorePass.toCharArray());
			}

			initRan = true;
		}
	}

	@Test
	public void testEncryptionDecryption() throws IOException {
		String message = "Super secret message";

		// prepare output stream with message
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(message.getBytes(StandardCharsets.UTF_8));

		// Encrypted output stream
		ByteArrayOutputStream encryptedStream = (ByteArrayOutputStream) signSignatureService.encryptDocument(stream, aliasPrivate);

		// Encrypted output stream to input stream
		InputStream inputStream = new ByteArrayInputStream(encryptedStream.toByteArray());

		// Decrypted input stream
		InputStream decryptedInputStream = signSignatureService.decryptDocument(inputStream, aliasPrivate, new GuardedString(privatePass));

		// Input stream to string
		String text = IOUtils.toString(decryptedInputStream, StandardCharsets.UTF_8.name());
		// Original message should be same as the decrypted and encrypted one
		assertEquals(message, text);
	}

	@Test(expected = SecurityException.class)
	public void testEncryptionDecryptionWrongKey() throws IOException {
		String message = "Super secret message";

		// prepare output stream with message
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(message.getBytes(StandardCharsets.UTF_8));

		// Encrypted output stream
		ByteArrayOutputStream encryptedStream = (ByteArrayOutputStream) signSignatureService.encryptDocument(stream, aliasPrivate);

		// Encrypted output stream to input stream
		InputStream inputStream = new ByteArrayInputStream(encryptedStream.toByteArray());

		// Decrypted input stream
		InputStream decryptedInputStream = signSignatureService.decryptDocument(inputStream, aliasPrivate1, new GuardedString(privatePass1));
	}

	@Test
	public void testSignDocumentAndValidate() throws IOException {
		String message = "Super secret message";
		// prepare output stream with message
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(message.getBytes(StandardCharsets.UTF_8));

		ByteArrayOutputStream signedStream = (ByteArrayOutputStream) signSignatureService.signDocument(stream, aliasPrivate, new GuardedString(privatePass));

		// Signed output stream to input stream
		InputStream inputStream = new ByteArrayInputStream(signedStream.toByteArray());

		// should be valid
		boolean isValid = signSignatureService.isDocumentValid(inputStream, aliasPrivate);
		assertTrue(isValid);
	}

	@Test
	public void testSignDocumentAndValidateWithWrongKey() throws IOException {
		String message = "Super secret message";
		// prepare output stream with message
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(message.getBytes(StandardCharsets.UTF_8));

		ByteArrayOutputStream signedStream = (ByteArrayOutputStream) signSignatureService.signDocument(stream, aliasPrivate, new GuardedString(privatePass));

		// Signed output stream to input stream
		InputStream inputStream = new ByteArrayInputStream(signedStream.toByteArray());

		// shouldn't be valid
		boolean isValid = signSignatureService.isDocumentValid(inputStream, aliasPrivate1);
		assertFalse(isValid);
	}

	@Test
	public void testSignAndEncryptAndDecrypt() throws IOException {
		String message = "Super secret message";
		// prepare output stream with message
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(message.getBytes(StandardCharsets.UTF_8));

		ByteArrayOutputStream signedAndEncrypted = (ByteArrayOutputStream) signSignatureService.signDocumentAndEncrypt(stream, aliasPrivate, new GuardedString(privatePass), aliasPrivate2);

		// Signed output stream to input stream
		InputStream inputStream = new ByteArrayInputStream(signedAndEncrypted.toByteArray());

		InputStream validatedAndDecrypted = signSignatureService.validateDocumentAndDecrypt(inputStream, aliasPrivate, aliasPrivate2, new GuardedString(privatePass2));

		// Input stream to string
		String text = IOUtils.toString(validatedAndDecrypted, StandardCharsets.UTF_8.name());
		// Original message should be same as the decrypted and encrypted one
		assertEquals(message, text);
	}

	public X509Certificate generate(KeyPair keyPair, String hashAlgorithm, String cn, int days)
			throws OperatorCreationException, CertificateException, CertIOException {
		Instant now = Instant.now();
		Date notBefore = Date.from(now);
		Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

		ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
		X500Name x500Name = new X500Name("CN=" + cn);
		X509v3CertificateBuilder certificateBuilder =
				new JcaX509v3CertificateBuilder(x500Name,
						BigInteger.valueOf(now.toEpochMilli()),
						notBefore,
						notAfter,
						x500Name,
						keyPair.getPublic())
						.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
						.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		return new JcaX509CertificateConverter()
				.setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey) throws OperatorCreationException {
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey) throws OperatorCreationException {
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
	}
}