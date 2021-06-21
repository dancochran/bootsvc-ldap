package org.dsc.ese.bootsvc.config;

import java.util.Collection;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.core.GrantedAuthority;

public class CustomUserDetailsContextMapper extends LdapUserDetailsMapper
{
    private LdapUser ldapUser = null;

	@Override
	public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities)
	{
		// Attributes attributes = ctx.getAttributes();
		UserDetails ldapUserDetails = super.mapUserFromContext(ctx, username, authorities);
		ldapUser = new LdapUser(ldapUserDetails);

		for (GrantedAuthority ga : ldapUser.getAuthorities())
		{
			System.out.println("*** Found authority: " + ga.getAuthority() + " for user: " + ldapUser.getUsername());
		}
		
		return ldapUser;
	}

	@Override
	public void mapUserToContext(UserDetails user, DirContextAdapter ctx)
	{

	}
	
}
