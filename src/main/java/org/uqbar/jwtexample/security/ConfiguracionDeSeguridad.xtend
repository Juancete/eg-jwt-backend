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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.uqbar.jwtexample.service.UserDetailService

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled=true)
class ConfiguracionDeSeguridad extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailService usuarioService

	@Autowired
	JwtRequestFilter jwtRequestFilter

	override protected configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(usuarioService).passwordEncoder(passwordEncoder());
	}

	override protected configure(HttpSecurity http) throws Exception {

		http
			.csrf().disable()
			.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter)
			.authorizeRequests().antMatchers("/login").permitAll()
			.anyRequest().authenticated()
			.and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

	}

	@Bean
	override AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean()
	}

	@Bean
	def BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder()
	}

}
