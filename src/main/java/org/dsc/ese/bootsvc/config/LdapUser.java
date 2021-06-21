package org.dsc.ese.bootsvc.config;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class LdapUser implements UserDetails
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 2720205134641419705L;
	
	private UserDetails ldapUserDetails;

	public LdapUser(UserDetails ldapUserDetails)
	{
		this.ldapUserDetails = ldapUserDetails;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities()
	{
		return ldapUserDetails.getAuthorities();
	}

	@Override
	public String getPassword()
	{
		return ldapUserDetails.getPassword();
	}

	@Override
	public String getUsername()
	{
		return ldapUserDetails.getUsername();
	}

	@Override
	public boolean isAccountNonExpired()
	{
		return ldapUserDetails.isAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked()
	{
		return ldapUserDetails.isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired()
	{
		return ldapUserDetails.isCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled()
	{
		return ldapUserDetails.isEnabled();
	}

}
