package com.newyeti.auth.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.newyeti.auth.models.ERole;
import com.newyeti.auth.models.Role;

@Repository
public interface RoleRepository extends MongoRepository<Role, String>{

  Optional<Role> findByName(ERole role);
  
} 