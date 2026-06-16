package com.innowise.authservice.service;

import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.entity.Credentials;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.TokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";
    private static final String CLAIM_TYPE = "type";
    private static final String CLAIM_ROLE = "role";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-expiration}")
    private long accessExp;

    @Value("${jwt.refresh-expiration}")
    private long refreshExp;

    public String generateToken(Credentials credentials, boolean isRefresh) {
        Map<String, Object> claims = isRefresh
                ? Map.of(CLAIM_TYPE, TYPE_REFRESH)
                : Map.of(CLAIM_TYPE, TYPE_ACCESS, CLAIM_ROLE, credentials.getRole().name());
        long expiration = isRefresh ? refreshExp : accessExp;

        return Jwts.builder()
                .claims(claims)
                .subject(credentials.getUserId().toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUserId(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            throw new TokenException("Token has expired");
        } catch (UnsupportedJwtException e) {
            throw new TokenException("Token is unsupported");
        } catch (MalformedJwtException e) {
            throw new TokenException("Token is malformed");
        } catch (SignatureException e) {
            throw new TokenException("Token signature is invalid");
        } catch (IllegalArgumentException e) {
            throw new TokenException("Token is empty or null");
        }
    }

    public ValidateResponse validateAndExtract(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!TYPE_ACCESS.equals(claims.get(CLAIM_TYPE))) {
                return new ValidateResponse(false, null, null);
            }

            String userId = claims.getSubject();
            Role role = Role.valueOf(claims.get(CLAIM_ROLE, String.class));
            return new ValidateResponse(true, userId, role);

        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException |
                 SignatureException | IllegalArgumentException e) {
            return new ValidateResponse(false, null, null);
        }
    }

    public boolean validateRefresh(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return TYPE_REFRESH.equals(claims.get(CLAIM_TYPE));
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException |
                 SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }
}
