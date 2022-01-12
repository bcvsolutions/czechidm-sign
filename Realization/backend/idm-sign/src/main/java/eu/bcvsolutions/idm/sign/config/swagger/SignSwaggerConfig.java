package eu.bcvsolutions.idm.sign.config.swagger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import eu.bcvsolutions.idm.core.api.config.swagger.AbstractSwaggerConfig;
import eu.bcvsolutions.idm.core.api.domain.ModuleDescriptor;
import eu.bcvsolutions.idm.sign.SignModuleDescriptor;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * Sign module swagger configuration
 *
 * @author Roman Kucera
 */
@Configuration
@ConditionalOnProperty(prefix = "springfox.documentation.swagger", name = "enabled", matchIfMissing = true)
public class SignSwaggerConfig extends AbstractSwaggerConfig {

	@Autowired private SignModuleDescriptor moduleDescriptor;

	@Override
	protected ModuleDescriptor getModuleDescriptor() {
		return moduleDescriptor;
	}

	@Bean
	public Docket signApi() {
		return api("eu.bcvsolutions.idm.rest");
	}
}
