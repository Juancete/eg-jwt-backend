package org.uqbar.jwtexample.domain

import org.eclipse.xtend.lib.annotations.Accessors
import org.uqbar.commons.model.Entity
import java.util.List
import com.fasterxml.jackson.annotation.JsonIgnore

@Accessors
class Usuario extends Entity{
	String username
	@JsonIgnore
	String password
	List<Rol> roles
	boolean habilitado
}