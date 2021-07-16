package org.uqbar.jwtexample.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.util.Date
import java.util.List
import java.util.Map
import java.util.function.Function
import javax.servlet.http.HttpServletRequest
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class TokenProvider {
	// *Nota: Rescatar SECRET de un archivo de configuración mas seguro..
	static final String SECRET = "123i!@#!@#$%Y^U&I*UJHGFDSZXcvbhjkuy"
	// private static final int EXPIRATION_TIME = 864000000; // 10 dias
	static final String TOKEN_PREFIX = "Bearer "
	static final String HEADER_STRING = "Authorization"
	static final String ROLE_IDENTIFICATION = "Roles"

	def static String extractUsername(String token) {
		extractClaim(token, [getSubject])
	}
	def static List<SimpleGrantedAuthority> extractAuthorities(String token) {
		rolesToAuthority(extractRoles(token))
	}
	def static List<SimpleGrantedAuthority> rolesToAuthority(List<String> roles){
		roles.map [ role |
					new SimpleGrantedAuthority(role)
				].toList
	}
	def static List<String> extractRoles(String token){
		extractAllClaims(token).get(ROLE_IDENTIFICATION,String).split(",")
	}
	def static Date extractExpiration(String token) {
		extractClaim(token, [getExpiration])
	}

	def static <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		val Claims claims = extractAllClaims(token)
		claimsResolver.apply(claims)
	}

	def static Claims extractAllClaims(String token) { Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).body }

	def static Boolean isTokenExpired(String token) {
		extractExpiration(token).before(new Date())
	}

	def static String generateToken(UserDetails userDetails) {
		val claims = newHashMap;
		claims.put(ROLE_IDENTIFICATION,userDetails.authorities.join(","))
		createToken(claims, userDetails.username)
	}

	def static createToken(Map<String, Object> claims, String subject) {

		return Jwts.builder()
		.setClaims(claims)
		.setSubject(subject)
		.setIssuedAt(new Date(System.currentTimeMillis()))
		.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
		.signWith(SignatureAlgorithm.HS256,SECRET)
		.compact()

	}

	def static Boolean validateToken(String token, UserDetails userDetails) {
		val String username = extractUsername(token)
		username.equals(userDetails.username) && !isTokenExpired(token)
	}

	def static getTokenFromHeader(HttpServletRequest request) {
		getHeaderString(request).substring(7)
	}

	def static isValidHeader(HttpServletRequest request) {
		val String authorizationHeader = getHeaderString(request)
		authorizationHeader !== null && authorizationHeader.startsWith(TOKEN_PREFIX)
	}

	def private static getHeaderString(HttpServletRequest request) {
		request.getHeader(HEADER_STRING)
	}

}
