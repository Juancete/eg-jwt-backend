package org.uqbar.jwtexample.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.uqbar.jwtexample.dao.RepoUsuario
import org.uqbar.jwtexample.domain.Usuario

@Service
class UserDetailService implements UserDetailsService {

	@Autowired
	RepoUsuario userRepository;

	override UserDetails loadUserByUsername(String username) {
		val Usuario user = userRepository.findByName(username)
		if (user === null) {
			throw new UsernameNotFoundException(username)
		}
		val authorities = user.getRoles().map [ role |
			new SimpleGrantedAuthority(role.nombre)
		].toList
		User.withUsername(username)//
        .password(user.getPassword())//
        .authorities(authorities)//
        .accountExpired(false)//
        .accountLocked(false)//
        .credentialsExpired(false)//
        .disabled(false)//
        .build()
	}
}
