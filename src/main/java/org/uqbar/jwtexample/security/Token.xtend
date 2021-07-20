package org.uqbar.jwtexample.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.util.Date
import java.util.List
import java.util.Map
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class Token {

	static final String SECRET = "123i!@#!@#$%Y^U&I*UJHGFDSZXcvbhjkuy"
	static final int TOKEN_LIFE = 1000 * 60 * 60 * 10
	static final int REFRESK_TOKEN_LIFE = 1000 * 60 * 60 * 10
	static final String ROLE_IDENTIFICATION = "Roles"
	static final String HEADER_STRING = "Authorization"
	static final String TOKEN_PREFIX = "Bearer "
	
	String data

	def static generateTokenFromHeader(HttpServletRequest request) {
		val String authorizationHeader = getHeaderString(request)
		if (authorizationHeader !== null && authorizationHeader.startsWith(TOKEN_PREFIX))
			new Token() => [data = authorizationHeader.substring(7)]
	}
	def private static getHeaderString(HttpServletRequest request) {
		request.getHeader(HEADER_STRING)
	}
		
	def static Token generateAccessToken(UserDetails userDetails) {
		val claims = newHashMap
		claims.put(ROLE_IDENTIFICATION, userDetails.authorities.join(","))
		createToken(claims, userDetails, TOKEN_LIFE)
	}

	def static Token generateRefreshToken(UserDetails userDetails) {
		createToken(newHashMap, userDetails,REFRESK_TOKEN_LIFE)
	}
	
	def static private createToken(Map<String, Object> _claims, UserDetails userDetails, int tokenLife) {
		
		val _data = Jwts.builder()
		.setHeaderParam("typ", "JWT")
		.setClaims(_claims)
		.setSubject(userDetails.username)
		.setIssuedAt(new Date(System.currentTimeMillis()))
		.setExpiration(new Date(System.currentTimeMillis() + tokenLife))
		.signWith(SignatureAlgorithm.HS256, SECRET)
		.compact()
		return new Token() => [data = _data]

	}
	def Boolean validateToken(String token, UserDetails userDetails) {
		val String username = extractUsername()
		username.equals(userDetails.username) && !isTokenExpired()
	}
	def Boolean isTokenExpired() {
		extractExpiration().before(new Date())
	}
	def private Claims extractAllClaims() {
		Jwts.parser().setSigningKey(SECRET).parseClaimsJws(data).body
	}
	def extractExpiration(){
		extractAllClaims().expiration
	}
	def extractUsername(){
		extractAllClaims().subject
	}
	def List<SimpleGrantedAuthority> extractAuthorities() {
		rolesToAuthority(extractRoles())
	}
	
	def static List<SimpleGrantedAuthority> rolesToAuthority(List<String> roles) {
		roles.map [ role | new SimpleGrantedAuthority(role)].toList
	}

	def List<String> extractRoles() {
		extractAllClaims().get(ROLE_IDENTIFICATION, String).split(",")
	}
	
	override toString(){ data }
}
