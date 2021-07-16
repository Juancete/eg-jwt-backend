package org.uqbar.jwtexample.security

import io.jsonwebtoken.Claims
import java.util.Date
import java.util.function.Function
import io.jsonwebtoken.Jwts
import org.springframework.security.core.userdetails.UserDetails
import io.jsonwebtoken.SignatureAlgorithm
import java.util.Map

class TokenProvider {
	//*Nota: Rescatar SECRET de un archivo de configuración mas seguro..
	static final String SECRET = "123i!@#!@#$%Y^U&I*UJHGFDSZXcvbhjkuy"
	//private static final int EXPIRATION_TIME = 864000000; // 10 dias
	//private static final String TOKEN_PREFIX = "Bearer";
	//private static final String HEADER_STRING = "Authorization";
	
	def static String extractUsername(String token) {
		return extractClaim(token, [getSubject])
	}
		
	def static Date extractExpiration(String token) {
		return extractClaim(token, [getExpiration])
	}
	
	def static <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		val Claims claims = extractAllClaims(token)
		return claimsResolver.apply(claims)
	}

	def static Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody()
	}
	
	def static Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date())
	}
	
	def static String generateToken(UserDetails userDetails) {
		val claims = newHashMap;
		return createToken(claims, userDetails.getUsername())
	}
	
	def static createToken(Map<String, Object> claims,String subject) {
		
		return Jwts.builder().setClaims(claims).setSubject(subject).
				setIssuedAt(new Date(System.currentTimeMillis())).
				setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10 )).
				signWith(SignatureAlgorithm.HS256, SECRET).
				compact()	
	
	}
	
	def static Boolean validateToken(String token, UserDetails userDetails) {
		val String username = extractUsername(token)
		return ( username.equals(userDetails.getUsername()) && !isTokenExpired(token) )
	}
}
