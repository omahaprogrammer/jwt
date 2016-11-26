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

import com.pazdev.jose.Algorithm;
import com.pazdev.jose.Header;
import com.pazdev.jose.JWE;
import com.pazdev.jose.JWK;
import com.pazdev.jose.JWS;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

/**
 *
 * @author Jonathan Paz <jonathan@pazdev.com>
 */
public final class JWT {
    public static final class Builder {
        private JWTClaims claims;
        private Algorithm signingAlgorithm;
        private JWK verifyingKeyJWT;
        private JWK encryptionKeyJWT;
        private String verifyingKeyId;
        private String encryptionKeyId;
        private Algorithm keyManagementAlgorithm;
        private Algorithm encryptionAlgorithm;
        private Key signingKey;
        private Key encryptionKey;
        private boolean specifyType = false;
        private boolean issuerInJWEHeader = false;
        private boolean subjectInJWEHeader = false;
        private boolean audienceInJWEHeader = false;

        public Builder withClaims(JWTClaims claims) {
            this.claims = claims;
            return this;
        }

        public Builder withSigningAlgorithm(Algorithm signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        public Builder withVerifyingKeyJWT(JWK verifyingKeyJWT) {
            this.verifyingKeyJWT = verifyingKeyJWT;
            return this;
        }

        public Builder withEncryptionKeyJWT(JWK encryptionKeyJWT) {
            this.encryptionKeyJWT = encryptionKeyJWT;
            return this;
        }

        public Builder withEncryptionKeyId(String id) {
            this.encryptionKeyId = id;
            return this;
        }

        public Builder withVerifyingKeyId(String id) {
            this.verifyingKeyId = id;
            return this;
        }
        public Builder withKeyManagementAlgorithm(Algorithm keyManagementAlgorithm) {
            this.keyManagementAlgorithm = keyManagementAlgorithm;
            return this;
        }

        public Builder withEncryptionAlgorithm(Algorithm encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            return this;
        }

        public Builder withSigningKey(Key signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        public Builder withEncryptionKey(Key encryptionKey) {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public void withSpecifyType(boolean specifyType) {
            this.specifyType = specifyType;
        }

        public void withIssuerInJWEHeader(boolean issuerInJWEHeader) {
            this.issuerInJWEHeader = issuerInJWEHeader;
        }

        public void withSubjectInJWEHeader(boolean subjectInJWEHeader) {
            this.subjectInJWEHeader = subjectInJWEHeader;
        }

        public void withAudienceInJWEHeader(boolean audienceInJWEHeader) {
            this.audienceInJWEHeader = audienceInJWEHeader;
        }

        public String build() {
            String retval = null;
            if (encryptionAlgorithm != null ^ encryptionKey != null) {
                throw new IllegalStateException("Both encryptionKey and encryptionAlgorithm must be set");
            }
            if (signingAlgorithm != null ^ signingKey != null) {
                throw new IllegalStateException("Both signingKey and signingAlgorithm must be set");
            }
            if (signingKey != null) {
                Header jwsHeader = Header.builder()
                        .withAlgorithm(signingAlgorithm)
                        .withJsonWebKey(verifyingKeyJWT)
                        .withKeyId(verifyingKeyId)
                        .withType(specifyType ? "JWT" : null)
                        .build();
                retval = JWS.builder()
                        .withSignature(jwsHeader, null, signingKey)
                        .withPayload(claims)
                        .build()
                        .toCompact();
            }
            if (encryptionKey != null) {
                String payload;
                String cty = null;
                if (retval != null) {
                    payload = retval;
                    cty = "JWT";
                } else {
                    payload = claims.toJson();
                }
                Header jweHeader = Header.builder()
                        .withAlgorithm(keyManagementAlgorithm)
                        .withEncryptionAlgorithm(encryptionAlgorithm)
                        .withJsonWebKey(encryptionKeyJWT)
                        .withKeyId(encryptionKeyId)
                        .withContentType(cty)
                        .withType(specifyType ? "JWT" : null)
                        .withIssuer(issuerInJWEHeader ? claims.getIssuer() : null)
                        .withSubject(subjectInJWEHeader ? claims.getSubject() : null)
                        .withAudience(audienceInJWEHeader ? claims.getAudience() : null)
                        .build();
                retval = JWE.builder()
                        .withKey(encryptionKey)
                        .withProtectedHeader(jweHeader)
                        .withPayload(payload)
                        .build()
                        .toCompact();
            }
            if (retval == null) {
                Header header = Header.builder().withAlgorithm(Algorithm.NONE).build();
                Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
                retval = String.format("%s.%s.",
                        encoder.encodeToString(header.toJson().getBytes(StandardCharsets.UTF_8)),
                        encoder.encodeToString(claims.toJson().getBytes(StandardCharsets.UTF_8)));
            }
            return retval;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static JWTClaims verify(String token, Key encryptionKey, Key verificationKey) {
        JWTClaims retval;
        // step 1
        if (!token.contains(".")) {
            throw new IllegalArgumentException("Malformatted token");
        }

        // step 2
        String[] parts = token.split("\\.");

        // step 3
        byte[] headerbytes = Base64.getUrlDecoder().decode(parts[0]);

        // step 4
        Header header = Header.parse(new String(headerbytes, StandardCharsets.UTF_8));
        
        // step 5
        if (header.getCritical() != null) {
            throw new IllegalArgumentException("Critical arguments not supported");
        }
        // the rest of step 5 happens during the next step
        // step 6
        switch (parts.length) {
            case 5: {
                // JWE
                if (encryptionKey == null) {
                    throw new IllegalArgumentException("encryption key is required");
                }
                String payload = JWE.parse(token).decryptString(encryptionKey);
                if ("JWT".equals(header.getContentType())) {
                    // encrypted signed-JWT
                    retval = verify(payload, verificationKey);
                } else {
                    retval = JWTClaims.parse(payload);
                }
                break;
            }
            case 3: {
                // JWS
                if (verificationKey == null) {
                    JWK jwk = header.getJsonWebKey();
                    verificationKey = jwk.getKeys().get("public");
                    if (verificationKey == null) {
                        throw new IllegalArgumentException("public key cannot be found and is not specified");
                    }
                }
                JWS jws = JWS.parse(token);
                String payload = jws.getPayload(StandardCharsets.UTF_8);
                if (!jws.verify(verificationKey)) {
                    throw new IllegalArgumentException("Signature does not verify");
                }
                if ("JWT".equals(header.getContentType())) {
                    // signed encrypted-JWT
                    retval = verify(payload, encryptionKey);
                } else {
                    retval = JWTClaims.parse(payload);
                }
                break;
            }
            default:
                throw new IllegalArgumentException("Unparseable JWT");
        }
        return retval;
    }

    public static JWTClaims verify(String token, Key key) {
        JWTClaims retval;
        // step 1
        if (!token.contains(".")) {
            throw new IllegalArgumentException("Malformatted token");
        }

        // step 2
        String[] parts = token.split("\\.");

        // step 3
        byte[] headerbytes = Base64.getUrlDecoder().decode(parts[0]);

        // step 4
        Header header = Header.parse(new String(headerbytes, StandardCharsets.UTF_8));
        
        // step 5
        if (header.getCritical() != null) {
            throw new IllegalArgumentException("Critical arguments not supported");
        }
        // the rest of step 5 happens during the next step
        // step 6
        switch (parts.length) {
            case 5: {
                // JWE
                if (key == null) {
                    throw new IllegalArgumentException("encryption key is required");
                }
                String payload = JWE.parse(token).decryptString(key);
                if ("JWT".equals(header.getContentType())) {
                    // encrypted signed-JWT
                    retval = verify(payload, null);
                } else {
                    retval = JWTClaims.parse(payload);
                }
                break;
            }
            case 3: {
                // JWE
                Key vkey;
                Key ekey;
                JWK jwk = header.getJsonWebKey();
                if (jwk != null) {
                    vkey = jwk.getKeys().get("public");
                    if (vkey == null) {
                        if (key == null) {
                            throw new IllegalArgumentException("public key cannot be found and is not specified");
                        } else {
                            vkey = key;
                            ekey = null;
                        }
                    } else {
                        ekey = key;
                    }
                } else {
                    vkey = key;
                    ekey = null;
                }
                JWS jws = JWS.parse(token);
                String payload = jws.getPayload(StandardCharsets.UTF_8);
                if (!jws.verify(vkey)) {
                    throw new IllegalArgumentException("Signature does not verify");
                }
                if ("JWT".equals(header.getContentType())) {
                    // signed encrypted-JWT
                    if (ekey != null) {
                        retval = verify(payload, ekey);
                    } else {
                        throw new UnsupportedOperationException("Encryption key is missing");
                    }
                } else {
                    retval = JWTClaims.parse(payload);
                }
                break;
            }
            default:
                throw new IllegalArgumentException("Unparseable JWT");
        }
        return retval;
    }

    public static JWTClaims verify(String token) {
        return verify(token, null);
    }

    private JWT() {
        throw new UnsupportedOperationException("Uninstantiatable class");
    }
}
