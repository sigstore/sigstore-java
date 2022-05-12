/*
 * Copyright 2022 The Sigstore Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.sigstore.testing;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;

// TODO: this can probably be replaces with a MockOauth2Server like in OidcClietTest
public class FakeOIDCServer implements AutoCloseable {

  public static final String USER = "test@example.com";

  private final RSAKey keyPair;
  private final HttpServer server;

  public FakeOIDCServer(HttpServer server, RSAKey keyPair) {
    this.server = server;
    this.keyPair = keyPair;
  }

  public URI getURI() {
    String address = server.getAddress().getHostString();
    int port = server.getAddress().getPort();
    return URI.create("http://" + address + ":" + port);
  }

  public static FakeOIDCServer startNewServer() throws IOException, JOSEException {
    RSAKey keyPair = new RSAKeyGenerator(2048).generate();
    HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    FakeOIDCServer testServer = new FakeOIDCServer(server, keyPair);
    server.createContext("/.well-known/openid-configuration", testServer::handleConfig);
    server.createContext("/keys", testServer::handleKeys);
    server.setExecutor(null); // creates a default executor
    server.start();
    return testServer;
  }

  @Override
  public void close() {
    server.stop(0);
  }

  public void handleConfig(HttpExchange t) throws IOException {
    HashMap<String, String> responseMap = new HashMap<>();
    responseMap.put("issuer", getURI().toString());
    responseMap.put("jwks_uri", getURI().resolve("/keys").toString());

    String jsonResp = new Gson().toJson(responseMap);
    t.sendResponseHeaders(200, jsonResp.length());
    OutputStream body = t.getResponseBody();
    body.write(jsonResp.getBytes());
    body.close();
  }

  public void handleKeys(HttpExchange t) throws IOException {
    String resp = new JWKSet(keyPair).toString(); // public keys only
    t.sendResponseHeaders(200, resp.length());
    OutputStream body = t.getResponseBody();
    body.write(resp.getBytes());
    body.close();
  }

  public String sign(String subject) throws JOSEException {
    RSASSASigner signer = new RSASSASigner(keyPair.toPrivateKey());
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(getURI().toString())
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plus(30, ChronoUnit.MINUTES)))
            .subject(subject)
            .audience("sigstore")
            .claim("email", USER)
            .claim("email_verified", true)
            .build();
    SignedJWT signedJWT = new SignedJWT(header, claims);
    signedJWT.sign(signer);
    return signedJWT.serialize();
  }

  public String getFulcioConfig() {
    String issuer = getURI().toString();
    return String.format(
        "{\"OIDCIssuers\":{ \"%s\": { \"IssuerURL\": \"%s\", \"ClientID\": \"sigstore\", \"Type\": \"email\"}}}",
        issuer, issuer);
  }
}
