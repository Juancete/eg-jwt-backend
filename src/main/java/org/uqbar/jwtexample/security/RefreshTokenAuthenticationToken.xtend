package org.uqbar.jwtexample.security

import java.util.Collection
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class RefreshTokenAuthenticationToken extends AbstractAuthenticationToken {
	
	UserDetails usuario
	
	new(UserDetails principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities)
		
		usuario = principal
	}
	
	override getCredentials() {
		null
	}
	
	override getPrincipal() {
		usuario
	}
	
}