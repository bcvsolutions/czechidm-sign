package eu.bcvsolutions.idm.sign.domain;

import java.util.Arrays;
import java.util.List;

import eu.bcvsolutions.idm.core.security.api.domain.BasePermission;
import eu.bcvsolutions.idm.core.security.api.domain.IdmBasePermission;
import eu.bcvsolutions.idm.core.security.api.domain.GroupPermission;
import eu.bcvsolutions.idm.sign.SignModuleDescriptor;

/**
 * Aggregate base permission. Name can't contain character '_' - its used for joining to authority name.
 *
 * @author Roman Kucera
 *
 */
public enum SignGroupPermission implements GroupPermission {

	/*
	 * Define your group permission there and example permission you can remove
	 */
	EXAMPLESIGN(
			IdmBasePermission.ADMIN);

	public static final String EXAMPLE_SIGN_ADMIN = "EXAMPLESIGN" + BasePermission.SEPARATOR + "ADMIN";

	private final List<BasePermission> permissions;

	private SignGroupPermission(BasePermission... permissions) {
		this.permissions = Arrays.asList(permissions);
	}
	
	@Override
	public List<BasePermission> getPermissions() {
		return permissions;
	}

	@Override
	public String getName() {
		return name();
	}

	@Override
	public String getModule() {
		return SignModuleDescriptor.MODULE_ID;
	}
}
