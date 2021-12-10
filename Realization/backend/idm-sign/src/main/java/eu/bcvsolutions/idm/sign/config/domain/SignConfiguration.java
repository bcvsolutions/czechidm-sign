package eu.bcvsolutions.idm.sign.config.domain;

import java.util.ArrayList;
import java.util.List;

import eu.bcvsolutions.idm.core.api.script.ScriptEnabled;
import eu.bcvsolutions.idm.core.api.service.Configurable;
import eu.bcvsolutions.idm.core.api.service.IdmConfigurationService;
import eu.bcvsolutions.idm.core.security.api.domain.GuardedString;
import eu.bcvsolutions.idm.sign.SignModuleDescriptor;

/**
 * Sign configuration - interface
 *
 * @author Roman Kucera
 */
public interface SignConfiguration extends Configurable, ScriptEnabled {

	String KEYSTORE_LOCATION = IdmConfigurationService.IDM_PRIVATE_PROPERTY_PREFIX + SignModuleDescriptor.MODULE_ID +
			"keystoreLocation";
	String KEYSTORE_PASSWORD = IdmConfigurationService.IDM_PRIVATE_PROPERTY_PREFIX + SignModuleDescriptor.MODULE_ID +
			"keystorePassword";

	@Override
	default String getConfigurableType() {
		return "configuration";
	}

	@Override
	default List<String> getPropertyNames() {
		List<String> properties = new ArrayList<>(); // we are not using superclass properties - enable and order does not make a sense here
		return properties;
	}

	String getKeystoreLocation();

	GuardedString getKeyStorePassword();
}
