package com.newyeti.auth.security.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.newyeti.auth.security.services.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtils {

  @Value("${newyeti.app.jwtSecret}")
  private String jwtSecret;

  @Value("${newyeti.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {
    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
    return Jwts.builder()
      .subject(userPrincipal.getUsername())
      .issuedAt(new Date())
      .expiration(new Date(new Date().getTime() + jwtExpirationMs))
      .signWith(key())
      .compact()
      ;

  }

  private SecretKey key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
  }

  public boolean validateJwtToken(String jwt) {
    try {
      Jwts.parser().verifyWith(key()).build().parse(jwt);
      return true;
    } catch(MalformedJwtException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
    } catch(ExpiredJwtException e) {
      log.error("JWT token has expired: {}", e.getMessage());
    } catch(UnsupportedJwtException e) {
      log.error("JWT token is unsupported: {}", e.getMessage());
    } catch(IllegalArgumentException e) {
      log.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }

  public String getUserNameFromJwtToken(String jwt) {
    return Jwts.parser().verifyWith(key()).build()
            .parseSignedClaims(jwt)
            .getPayload()
            .getSubject();
  }
  
}
