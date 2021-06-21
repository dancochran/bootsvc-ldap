package org.dsc.ese.bootsvc.config;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.ldap.LdapProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(LdapProperties.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
	private final LdapProperties ldapProperties;
	
	@Value("${ldap.userDnPattern}")
    private String userDnPattern;
	@Value("${ldap.groupSearchBase}")
    private String groupSearchBase;
	@Value("${ldap.groupSearchFilter}")
    private String groupSearchFilter;
	
	public SecurityConfig(LdapProperties ldapProperties)
	{
		super();
		this.ldapProperties = ldapProperties;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		// ROLE_DEVELOPERS
		// ROLE_ADMINS
		// ROLE_TESTERS
		http.authorizeRequests().antMatchers(HttpMethod.GET, "/customer").hasAnyAuthority("ROLE_DEVELOPERS","ROLE_TESTERS")	
		.antMatchers(HttpMethod.POST, "/customer").hasAuthority("ROLE_TESTERS")
		.antMatchers(HttpMethod.PUT, "/customer").authenticated()
		.antMatchers(HttpMethod.DELETE, "/customer").hasAuthority("ROLE_ADMINS")
		.antMatchers(HttpMethod.GET, "/actuator/**")
		.permitAll().antMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**")
		.permitAll().anyRequest().authenticated().and().httpBasic();

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.cors().and().csrf().disable();
	}	
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		String url = String.format("%s/%s", ldapProperties.getUrls()[0], ldapProperties.getBase());

		auth.ldapAuthentication()
		.userDetailsContextMapper(danUserDetailsContextMapper())
			.userDnPatterns(userDnPattern)
			.groupSearchBase(groupSearchBase)
			.groupSearchFilter(groupSearchFilter)
			.contextSource()
				.url(url)
				.managerDn(ldapProperties.getUsername())
				.managerPassword(ldapProperties.getPassword());
				
			
	}
	
	/***
	 * more explicit custom classes CustomUserDetailsContextMapper and LdapUser
	@Bean
	public CustomUserDetailsContextMapper customUserDetailsContextMapper()
	{
		return new CustomUserDetailsContextMapper();
	}
	***/
	
	// simpler, without custom mapper class and user class
	@Bean
	public UserDetailsContextMapper danUserDetailsContextMapper()
	{
		return new LdapUserDetailsMapper() {
			@Override
			public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
					Collection<? extends GrantedAuthority> authorities) {
				UserDetails ldapUserDetails = super.mapUserFromContext(ctx, username, authorities);
				return ldapUserDetails;
			}
		};
	}

}
