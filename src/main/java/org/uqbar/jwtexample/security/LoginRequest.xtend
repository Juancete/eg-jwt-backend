package org.uqbar.jwtexample.security

import org.eclipse.xtend.lib.annotations.Accessors

@Accessors
class LoginRequest {
	String username
	String password
}