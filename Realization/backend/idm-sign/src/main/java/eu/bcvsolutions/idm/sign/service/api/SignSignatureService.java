package eu.bcvsolutions.idm.sign.service.api;

import java.io.InputStream;
import java.io.OutputStream;

import eu.bcvsolutions.idm.core.security.api.domain.GuardedString;

public interface SignSignatureService {

	OutputStream signDocumentAndEncrypt(OutputStream document, String keyAliasSign, GuardedString privatePassSign, String keyAliasEncrypt);

	OutputStream signDocument(OutputStream document, String keyAlias, GuardedString privatePass);

	boolean isDocumentValid(InputStream document, String keyAlias);

	InputStream validateDocumentAndDecrypt(InputStream document, String keyAliasSign, String keyAliasDecrypt, GuardedString privatePassDecrypt);

	OutputStream encryptDocument(OutputStream document, String keyAlias);

	InputStream decryptDocument(InputStream document, String keyAlias, GuardedString privatePass);
}
