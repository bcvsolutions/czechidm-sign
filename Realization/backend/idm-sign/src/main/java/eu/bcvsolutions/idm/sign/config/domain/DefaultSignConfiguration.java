package eu.bcvsolutions.idm.sign.config.domain;

import org.springframework.stereotype.Component;

import eu.bcvsolutions.idm.core.api.config.domain.AbstractConfiguration;
import eu.bcvsolutions.idm.core.security.api.domain.GuardedString;

/**
 * Sign configuration - implementation
 *
 * @author Roman Kucera
 *
 */
@Component("signConfiguration")
public class DefaultSignConfiguration
		extends AbstractConfiguration
		implements SignConfiguration {

	@Override
	public String getKeystoreLocation() {
		return getConfigurationService().getValue(KEYSTORE_LOCATION);
	}

	@Override
	public GuardedString getKeyStorePassword() {
		return getConfigurationService().getGuardedValue(KEYSTORE_PASSWORD);
	}
}
