/*
 * Copyright 2016 Jonathan Paz <jonathan@pazdev.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pazdev.jwt;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
@JsonDeserialize(builder = JWTClaims.Builder.class)
public class JWTClaims {
    @JsonProperty("iss")
    private final String issuer;
    @JsonProperty("sub")
    private final String subject;
    @JsonProperty("aud")
    private final String audience;
    @JsonProperty("exp")
    @JsonFormat(shape = JsonFormat.Shape.NUMBER, pattern = "s")
    private final Instant expirationTime;
    @JsonProperty("nbf")
    @JsonFormat(shape = JsonFormat.Shape.NUMBER, pattern = "s")
    private final Instant notBefore;
    @JsonProperty("iat")
    @JsonFormat(shape = JsonFormat.Shape.NUMBER, pattern = "s")
    private final Instant issuedAt;
    @JsonProperty("jti")
    private final String jwtId;
    private final Map<String, Object> claims;

    protected JWTClaims(String issuer, String subject, String audience, Instant expirationTime, Instant notBefore, Instant issuedAt, String jwtId , Map<String, Object> claims) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.expirationTime = expirationTime;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.claims = claims;
    }

    @JsonPOJOBuilder
    public static class Builder {
        protected String issuer;
        protected String subject;
        protected String audience;
        protected Instant expirationTime;
        protected Instant notBefore;
        protected Instant issuedAt;
        protected String jwtId;
        protected final HashMap<String, Object> claims = new HashMap<>();

        @JsonProperty("iss")
        public Builder withIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        @JsonProperty("sub")
        public Builder withSubject(String subject) {
            this.subject = subject;
            return this;
        }

        @JsonProperty("aud")
        public Builder withAudience(String audience) {
            this.audience = audience;
            return this;
        }

        @JsonProperty("exp")
        public Builder withExpirationTime(Instant expirationTime) {
            this.expirationTime = expirationTime;
            return this;
        }

        @JsonProperty("nbf")
        public Builder withNotBefore(Instant notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        @JsonProperty("iat")
        public Builder withIssuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        @JsonProperty("jti")
        public Builder withJwtId(String jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        @JsonAnySetter
        public Builder withClaim(String key, Object value) {
            this.claims.put(key, value);
            return this;
        }

        public Builder withClaims(Map<String, Object> claims) {
            if (claims != null) {
                this.claims.putAll(claims);
            }
            return this;
        }
        
        public JWTClaims build() {
            return new JWTClaims(issuer, subject, audience, expirationTime, notBefore, issuedAt, jwtId, ImmutableMap.copyOf(claims));
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getAudience() {
        return audience;
    }

    public Instant getExpirationTime() {
        return expirationTime;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public String getJwtId() {
        return jwtId;
    }

    @JsonAnyGetter
    public Map<String, Object> getClaims() {
        return claims;
    }

    public Object getClaim(String key) {
        return claims.get(key);
    }

    public <T> T getClaim(String key, Class<T> cls) {
        return cls.cast(claims.get(key));
    }

    public String toJson() {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static JWTClaims parse(String json) {
        ObjectMapper om = new ObjectMapper();
        om.setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        try {
            return om.readValue(json, JWTClaims.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
