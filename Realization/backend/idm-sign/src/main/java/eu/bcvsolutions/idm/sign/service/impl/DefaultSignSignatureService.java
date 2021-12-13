package eu.bcvsolutions.idm.sign.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.io.IOUtils;
import org.apache.cxf.rs.security.jose.jwa.ContentAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.KeyAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwe.AesCbcHmacJweDecryption;
import org.apache.cxf.rs.security.jose.jwe.AesCbcHmacJweEncryption;
import org.apache.cxf.rs.security.jose.jwe.JweDecryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.JweEncryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.JweException;
import org.apache.cxf.rs.security.jose.jwe.JweHeaders;
import org.apache.cxf.rs.security.jose.jwe.JweUtils;
import org.apache.cxf.rs.security.jose.jwe.KeyDecryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.KeyEncryptionProvider;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsCompactProducer;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rt.security.crypto.CryptoUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import eu.bcvsolutions.idm.core.api.exception.CoreException;
import eu.bcvsolutions.idm.core.security.api.domain.GuardedString;
import eu.bcvsolutions.idm.sign.config.domain.SignConfiguration;
import eu.bcvsolutions.idm.sign.service.api.SignSignatureService;

@Service
public class DefaultSignSignatureService implements SignSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultSignSignatureService.class);

	private final String KEY_ALGO_ENCRYPT = "RSA-OAEP";
	private final String KEY_ALGO_SIGN = "RS256";

	@Autowired
	private SignConfiguration signConfiguration;

	public DefaultSignSignatureService() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Override
	public OutputStream signDocumentAndEncrypt(OutputStream document, String keyAlias, GuardedString privatePass) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "keyAlias can't be null");
		Assert.notNull(privatePass, "privatePass can't be null");

		return encryptDocument(signDocument(document, keyAlias, privatePass), keyAlias);
	}

	@Override
	public OutputStream signDocument(OutputStream document, String keyAlias, GuardedString privatePass) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "keyAlias can't be null");
		Assert.notNull(privatePass, "privatePass can't be null");

		ByteArrayOutputStream outputStream = (ByteArrayOutputStream) document;
		String content = outputStream.toString();

		JwsHeaders headers = new JwsHeaders(SignatureAlgorithm.RS256);
		JwsCompactProducer jwsProducer = new JwsCompactProducer(headers, content);
		try {
			KeyStore keyStore = loadKeystore();
			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(privatePass.asString().toCharArray()));
			PublicKey publicRsaKey = pkEntry.getCertificate().getPublicKey();
			PrivateKey privateRsaKey = pkEntry.getPrivateKey();

			JsonWebKey webKeyPrivate = JwkUtils.fromRSAPrivateKey((RSAPrivateKey) privateRsaKey, KEY_ALGO_SIGN);
			JsonWebKey webKeyPublic = JwkUtils.fromRSAPublicKey((RSAPublicKey) publicRsaKey, KEY_ALGO_ENCRYPT);

			// put public info into private key, otherwise getKeyDecryptionProvider will fail on nullpointer, because this property can't be null
			webKeyPrivate.setKeyProperty("e", webKeyPublic.getKeyProperty("e"));

			// Sign
			String jwsSequence = jwsProducer.signWith(webKeyPrivate);
			OutputStream out = new ByteArrayOutputStream();
			out.write(jwsSequence.getBytes(StandardCharsets.UTF_8));
			return out;
		} catch (IOException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			throw new CoreException(e);
		}
	}

	@Override
	public boolean isDocumentValid(InputStream document, String keyAlias) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "keyAlias can't be null");

		try {
			String jweContent = IOUtils.toString(document, StandardCharsets.UTF_8.name());
			JwsCompactConsumer jwsConsumer = new JwsCompactConsumer(jweContent);
			PublicKey publicRsaKey = CryptoUtils.loadPublicKey(loadKeystore(), keyAlias);

			JsonWebKey webKey = JwkUtils.fromRSAPublicKey((RSAPublicKey) publicRsaKey, KEY_ALGO_SIGN);
			return jwsConsumer.verifySignatureWith(webKey);
		} catch (IOException e) {
			throw new CoreException(e);
		}
	}

	@Override
	public InputStream validateDocumentAndDecrypt(InputStream document, String keyAlias, GuardedString privatePass) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "keyAlias can't be null");
		Assert.notNull(privatePass, "privatePass can't be null");

		try {
			InputStream decryptedStream = decryptDocument(document, keyAlias, privatePass);
			String jwsContent = IOUtils.toString(decryptedStream, StandardCharsets.UTF_8.name());
			PublicKey publicRsaKey = CryptoUtils.loadPublicKey(loadKeystore(), keyAlias);
			// Validate
			JwsCompactConsumer jwsConsumer = new JwsCompactConsumer(jwsContent);
			JsonWebKey webKey = JwkUtils.fromRSAPublicKey((RSAPublicKey) publicRsaKey, KEY_ALGO_SIGN);
			boolean isValid = jwsConsumer.verifySignatureWith(webKey);
			if (isValid) {
				return IOUtils.toInputStream(jwsConsumer.getDecodedJwsPayload(), StandardCharsets.UTF_8);
			}
			throw new CoreException("Signature is not valid");
		} catch (IOException e) {
			throw new CoreException(e);
		}
	}

	@Override
	public OutputStream encryptDocument(OutputStream document, String keyAlias) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "publicKeyAlias can't be null");

		ByteArrayOutputStream outputStream = (ByteArrayOutputStream) document;
		String content = outputStream.toString();
		try {

			KeyStore keyStore = loadKeystore();
			Certificate certificate = keyStore.getCertificate(keyAlias);
			PublicKey publicRsaKey = certificate.getPublicKey();
			JsonWebKey webKey = JwkUtils.fromRSAPublicKey((RSAPublicKey) publicRsaKey, KEY_ALGO_ENCRYPT);

			KeyEncryptionProvider keyEncryptionAlgo = JweUtils.getKeyEncryptionProvider(webKey);
			JweEncryptionProvider encryptor = new AesCbcHmacJweEncryption(ContentAlgorithm.A128CBC_HS256, keyEncryptionAlgo);

			JweHeaders headers = new JweHeaders(KeyAlgorithm.RSA_OAEP, ContentAlgorithm.A128CBC_HS256);

			String jweOut = encryptor.encrypt(content.getBytes(StandardCharsets.UTF_8), headers);

			OutputStream out = new ByteArrayOutputStream();
			out.write(jweOut.getBytes(StandardCharsets.UTF_8));
			return out;
		} catch (IOException | JweException | KeyStoreException e) {
			throw new CoreException(e);
		}
	}

	@Override
	public InputStream decryptDocument(InputStream document, String keyAlias, GuardedString privatePass) {
		Assert.notNull(document, "Document can't be null");
		Assert.notNull(keyAlias, "keyAlias can't be null");
		Assert.notNull(privatePass, "privatePass can't be null");

		try {
			String jweContent = IOUtils.toString(document, StandardCharsets.UTF_8.name());

			KeyStore keyStore = loadKeystore();
			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(privatePass.asString().toCharArray()));
			PublicKey publicRsaKey = pkEntry.getCertificate().getPublicKey();
			PrivateKey privateRsaKey = pkEntry.getPrivateKey();

			JsonWebKey webKeyPublic = JwkUtils.fromRSAPublicKey((RSAPublicKey) publicRsaKey, KEY_ALGO_ENCRYPT);
			JsonWebKey webKeyPrivate = JwkUtils.fromRSAPrivateKey((RSAPrivateKey) privateRsaKey, KEY_ALGO_ENCRYPT);

			// put public info into private key, otherwise getKeyDecryptionProvider will fail on nullpointer, because this property can't be null
			webKeyPrivate.setKeyProperty("e", webKeyPublic.getKeyProperty("e"));

			KeyDecryptionProvider keyDecryptionAlgo = JweUtils.getKeyDecryptionProvider(webKeyPrivate);
			JweDecryptionProvider decryptor = new AesCbcHmacJweDecryption(keyDecryptionAlgo, ContentAlgorithm.A128CBC_HS256);

			String decryptedText = decryptor.decrypt(jweContent).getContentText();

			return IOUtils.toInputStream(decryptedText, StandardCharsets.UTF_8);
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new CoreException(e);
		}
	}

	private KeyStore loadKeystore() {
		String keystoreLocation = signConfiguration.getKeystoreLocation();
		GuardedString keyStorePassword = signConfiguration.getKeyStorePassword();

		Assert.hasLength(keystoreLocation, "Keystore location must be set");
		Assert.notNull(keyStorePassword, "Keystore password must be set");

		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(keystoreLocation), keyStorePassword.asString().toCharArray());
			return ks;
		} catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
			throw new CoreException(e);
		}
	}

}
