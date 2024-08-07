package com.newyeti.auth.payload.response;

import java.util.List;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class JwtResponse {
  private final String token;
  private String type =  "Bearer";
  private final String id;
  private final String username;
  private final String email;
  private final List<String> roles;
  
}
