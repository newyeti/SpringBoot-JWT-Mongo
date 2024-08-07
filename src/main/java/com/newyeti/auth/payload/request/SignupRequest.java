package com.newyeti.auth.payload.request;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class SignupRequest {

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
  
  private Set<String> roles;

}
