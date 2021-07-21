package org.uqbar.jwtexample.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.io.IOException
import java.util.Date
import java.util.List
import java.util.Map
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

abstract class Token {

	protected String data

	def static createToken(Map<String, Object> claims, UserDetails userDetails, int tokenLife, String secret) {

		Jwts.builder().setHeaderParam("typ", "JWT").setClaims(claims).setSubject(userDetails.username).setIssuedAt(
			new Date(System.currentTimeMillis())).setExpiration(new Date(System.currentTimeMillis() + tokenLife)).
			signWith(SignatureAlgorithm.HS256, secret).compact()

	}

	def Boolean validateToken(String token, UserDetails userDetails) {
		val String username = extractUsername()
		username.equals(userDetails.username) && !isTokenExpired()
	}

	def Boolean isTokenExpired() {
		extractExpiration().before(new Date())
	}

	def protected Claims extractAllClaims() {
		Jwts.parser().setSigningKey(secret).parseClaimsJws(data).body
	}
	
	def abstract String getSecret()
	
	def extractExpiration() {
		extractAllClaims().expiration
	}

	def extractUsername() {
		extractAllClaims().subject
	}
	override equals(Object o) {
		try {
			val Token otro = o as Token
			return otro.data.equals(data)
		} catch (ClassCastException e) {
			return false
		}
	}
	
	override hashCode() {
		data.hashCode
	}
	override toString() { data }
}

class RefreshToken extends Token {
	static final String REFRESH_SECRET = ";a;sldkfasdQ$#%#$%@!#DFFAsd09234"
	static final int REFRESK_TOKEN_LIFE = 1000 * 60 * 60 * 10
	
	def static build(String token){
		new RefreshToken() =>[
			data = token
		]
	}
	def static build(UserDetails userDetails) {
		new RefreshToken() =>[
			data = RefreshToken.createToken(newHashMap, userDetails, REFRESK_TOKEN_LIFE, REFRESH_SECRET)		
		]
	}
	
	override getSecret() {
		REFRESH_SECRET
	}
	
}

class AuthorizationToken extends Token {
	static final String HEADER_STRING = "Authorization"
	static final String TOKEN_PREFIX = "Bearer "
	static final String ROLE_IDENTIFICATION = "Roles"
	static final String SECRET = "123i!@#!@#$%Y^U&I*UJHGFDSZXcvbhjkuy"

	static final int TOKEN_LIFE = 1000 * 60 * 60 * 10

	def static build(UserDetails userDetails){
		val roles = generateRoles(userDetails)
		new AuthorizationToken() =>[
			data = AuthorizationToken.createToken(roles, userDetails, TOKEN_LIFE, SECRET)		
		]
	}
	
	def static build(HttpServletRequest request) {
		val String authorizationHeader = getHeaderString(request)
		if (authorizationHeader !== null && authorizationHeader.startsWith(TOKEN_PREFIX))
			new AuthorizationToken() => [data = authorizationHeader.substring(7)]
		else
			throw new IOException()

	}

	def private static getHeaderString(HttpServletRequest request) {
		request.getHeader(HEADER_STRING)
	}

	def static Map<String, Object> generateRoles(UserDetails userDetails) {
		val claims = newHashMap
		claims.put(ROLE_IDENTIFICATION, userDetails.authorities.join(","))
		claims
	}

	def List<String> extractRoles() {
		extractAllClaims().get(ROLE_IDENTIFICATION, String).split(",")
	}

	def List<SimpleGrantedAuthority> extractAuthorities() {
		rolesToAuthority(extractRoles())
	}

	def static List<SimpleGrantedAuthority> rolesToAuthority(List<String> roles) {
		roles.map[role|new SimpleGrantedAuthority(role)].toList
	}
	
	override getSecret() {
		SECRET
	}

}
