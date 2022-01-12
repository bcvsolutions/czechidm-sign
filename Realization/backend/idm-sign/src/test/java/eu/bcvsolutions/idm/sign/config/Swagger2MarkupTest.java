
package eu.bcvsolutions.idm.sign.config;

import org.junit.Test;

import eu.bcvsolutions.idm.sign.SignModuleDescriptor;
import eu.bcvsolutions.idm.test.api.AbstractSwaggerTest;


/**
 * Static swagger generation to sources - will be used as input for swagger2Markup build
 *
 * @author Roman Kucera
 *
 */
public class Swagger2MarkupTest extends AbstractSwaggerTest {

	@Test
	public void testConvertSwagger() throws Exception {
		super.convertSwagger(SignModuleDescriptor.MODULE_ID);
	}

}
