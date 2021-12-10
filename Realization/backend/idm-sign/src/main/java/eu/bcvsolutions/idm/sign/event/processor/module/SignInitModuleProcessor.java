package eu.bcvsolutions.idm.sign.event.processor.module;

import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Description;
import eu.bcvsolutions.idm.core.api.dto.ModuleDescriptorDto;
import eu.bcvsolutions.idm.core.api.event.CoreEvent;
import eu.bcvsolutions.idm.core.api.event.DefaultEventResult;
import eu.bcvsolutions.idm.core.api.event.EntityEvent;
import eu.bcvsolutions.idm.core.api.event.EventResult;
import eu.bcvsolutions.idm.core.api.event.processor.AbstractInitApplicationProcessor;
import eu.bcvsolutions.idm.sign.SignModuleDescriptor;

/**
 * Initialize Sign module.
 *
 * @author Roman Kucera
 *
 */
@Component(SignInitModuleProcessor.PROCESSOR_NAME)
@Description("Initialize Sign module.")
public class SignInitModuleProcessor extends AbstractInitApplicationProcessor {
	
	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SignInitModuleProcessor.class);
	//
	public static final String PROCESSOR_NAME = "sign-init-module-processor";

	@Override
	public boolean conditional(EntityEvent<ModuleDescriptorDto> event) {
		return super.conditional(event) && isInitDataEnabled();
	}

	@Override
	public EventResult<ModuleDescriptorDto> process(EntityEvent<ModuleDescriptorDto> event) {
		LOG.info("Module [{}] initialization", SignModuleDescriptor.MODULE_ID);
		//
		return new DefaultEventResult<>(event, this);
	}
	
	@Override
	public int getOrder() {
		// after admin identity is created
		return CoreEvent.DEFAULT_ORDER + 300;
	}
}
