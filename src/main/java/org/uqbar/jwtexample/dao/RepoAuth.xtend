package org.uqbar.jwtexample.dao

import java.util.Map
import org.springframework.stereotype.Repository
import org.uqbar.jwtexample.security.RefreshToken
import org.uqbar.jwtexample.security.Token

@Repository
class RepoAuth {
	Map<String,RefreshToken> tokens = newHashMap
	
	def add(String user, RefreshToken token){
		val otroToken = tokens.putIfAbsent(user, token)
		if (otroToken !== null){
			tokens.remove(user)
			tokens.put(user,token)
		}
	}
	
	def verifyToken(String username, Token token) {
		val myToken = tokens.get(username)
		myToken !== null && myToken.equals(token)
	}
	
}