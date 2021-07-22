package org.uqbar.jwtexample.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.uqbar.jwtexample.dao.RepoAuth
import org.uqbar.jwtexample.security.filters.JWTAuthenticationFilter
import org.uqbar.jwtexample.security.filters.JWTAuthorizationFilter
import org.uqbar.jwtexample.security.filters.JWTRefreshFilter
import org.uqbar.jwtexample.service.UserDetailService

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled=true)
class ConfiguracionDeSeguridad extends WebSecurityConfigurerAdapter {
	@Autowired
	RepoAuth repo
	
	@Autowired
	UserDetailService usuarioService

	@Autowired
	UserDetailService userDetailService

	override protected configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(usuarioService).passwordEncoder(passwordEncoder())
	}

	override protected configure(HttpSecurity http) throws Exception {

		http
			.csrf().disable()
			.authorizeRequests().antMatchers("/login").permitAll()
			.anyRequest().authenticated()
			.and()
            .addFilter(new JWTAuthenticationFilter(authenticationManager(), userDetailService, repo))
            .addFilterBefore(new JWTRefreshFilter("/refreshToken",authenticationManager(),userDetailService, repo),JWTAuthenticationFilter)
            .addFilter(new JWTAuthorizationFilter(authenticationManager()))
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

	}

	@Bean
	override AuthenticationManager authenticationManagerBean() throws Exception {
		super.authenticationManagerBean()
	}

	@Bean
	def BCryptPasswordEncoder passwordEncoder() {
		new BCryptPasswordEncoder()
	}

}
