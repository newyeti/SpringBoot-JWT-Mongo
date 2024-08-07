package com.newyeti.auth.models;

import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Document(collection = "users")
@Data
@RequiredArgsConstructor
public class User {

  @Id
  private String id;
  
  @NotBlank
  @Size(min = 3, max = 20)
  private final String username;

  @NotBlank
  @Size(max = 50)
  @Email
  private final String email;

  @NotBlank
  @Size(min = 6, max = 40)
  private final String password;

  @DBRef
  private Set<Role> roles = new HashSet<>();

}
