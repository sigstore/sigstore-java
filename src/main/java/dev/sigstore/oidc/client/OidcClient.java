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
package dev.sigstore.oidc.client;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Key;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import dev.sigstore.http.HttpProvider;
import java.io.IOException;
import java.util.Arrays;
import javax.annotation.Nullable;

/** A client to obtain oidc tokens for use with sigstore. */
public class OidcClient {

  private static final String ID_TOKEN_KEY = "id_token";
  private static final String DEFAULT_CLIENT_ID = "sigstore";
  private static final String DEFAULT_ISSUER = "https://oauth2.sigstore.dev/auth";
  private static final String WELL_KNOWN_CONFIG = "/.well-known/openid-configuration";

  private final HttpProvider httpProvider;
  private final String clientId;
  private final String issuer;
  private final BrowserHandler browserHandler;

  private OidcClient(
      HttpProvider httpProvider, String issuer, String clientId, BrowserHandler browserHandler) {
    this.httpProvider = httpProvider;
    this.clientId = clientId;
    this.issuer = issuer;
    this.browserHandler = browserHandler;
  }

  public static OidcClient.Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private HttpProvider httpProvider;
    private String clientId = DEFAULT_CLIENT_ID;
    private String issuer = DEFAULT_ISSUER;
    private BrowserHandler browserHandler = null;

    private Builder() {}

    /** Configure the http properties, see {@link HttpProvider} */
    public Builder setHttpProvider(HttpProvider httpProvider) {
      this.httpProvider = httpProvider;
      return this;
    }

    /** The client id used in the oidc request, defaults to {@value DEFAULT_CLIENT_ID}. */
    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /** The issuer of the oidc tokens (the oidc service) {@value DEFAULT_ISSUER}. */
    public Builder setIssuer(String issuer) {
      this.issuer = issuer;
      return this;
    }

    /**
     * Alternative to default browser behavior, only use if you truly need to open with some sort of
     * custom browser, like in test or headless environments.
     */
    public Builder setBrowser(BrowserHandler browserHandler) {
      this.browserHandler = browserHandler;
      return this;
    }

    public OidcClient build() {
      HttpProvider hp = httpProvider != null ? httpProvider : HttpProvider.builder().build();
      BrowserHandler bh =
          browserHandler != null
              ? browserHandler
              : new AuthorizationCodeInstalledApp.DefaultBrowser()::browse;
      return new OidcClient(hp, issuer, clientId, bh);
    }
  }

  /**
   * Get an id token from the oidc provider with openid and email scopes
   *
   * @param expectedEmailAddress optional parameter to verify the subject email address does indeed
   *     match the value in the id token
   * @return an openid token with additional email scopes
   * @throws OidcException if an error occurs doing the authorization flow
   */
  public EmailIdToken getIDToken(@Nullable String expectedEmailAddress) throws OidcException {
    JsonFactory jsonFactory = new GsonFactory();
    HttpTransport httpTransport = httpProvider.getHttpTransport();
    DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();
    OIDCEndpoints endpoints;
    try {
      endpoints = parseDiscoveryDocument(jsonFactory, httpTransport);
    } catch (IOException e) {
      // TODO: maybe a more descriptive exception message
      throw new OidcException(
          "ioexception obtaining and parsing oidc configuration for " + issuer, e);
    }
    AuthorizationCodeFlow.Builder flowBuilder =
        new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(),
                httpTransport,
                jsonFactory,
                new GenericUrl(endpoints.getTokenEndpoint()),
                new ClientParametersAuthentication(clientId, null),
                clientId,
                endpoints.getAuthEndpoint())
            .enablePKCE()
            .setScopes(Arrays.asList("openid", "email"))
            .setCredentialCreatedListener(
                (credential, tokenResponse) ->
                    memStoreFactory
                        .getDataStore("user")
                        .set(ID_TOKEN_KEY, tokenResponse.get(ID_TOKEN_KEY).toString()));
    AuthorizationCodeInstalledApp app =
        new AuthorizationCodeInstalledApp(
            flowBuilder.build(), new LocalServerReceiver(), browserHandler::openBrowser);

    String idTokenString = null;
    IdToken parsedIdToken = null;
    try {
      app.authorize("user");
      idTokenString = (String) memStoreFactory.getDataStore("user").get(ID_TOKEN_KEY);
      parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
      IdTokenVerifier idTokenVerifier =
          new IdTokenVerifier.Builder()
              .setIssuer(issuer)
              .setCertificatesLocation(endpoints.getJwksUri())
              .build();
      if (!idTokenVerifier.verify(parsedIdToken)) {
        throw new OidcException("id token could not be verified");
      }
    } catch (IOException e) {
      // TODO: maybe a more descriptive exception message
      throw new OidcException("ioexception during oidc handshake", e);
    }

    String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
    boolean emailVerified = (boolean) parsedIdToken.getPayload().get("email_verified");
    if (expectedEmailAddress != null && !emailFromIDToken.equals(expectedEmailAddress)) {
      throw new OidcException(
          String.format(
              "email in ID token '%s' does not match address specified to plugin '%s'",
              emailFromIDToken, expectedEmailAddress));
    } else if (Boolean.FALSE.equals(emailVerified)) {
      throw new OidcException(
          String.format(
              "identity provider '%s' reports email address '%s' has not been verified",
              parsedIdToken.getPayload().getIssuer(), expectedEmailAddress));
    }

    return new EmailIdToken(emailFromIDToken, idTokenString);
  }

  // Parses a oidc discovery document to discover other endpoints. This method does not
  // parse all the values, only the endpoints we care about.
  OIDCEndpoints parseDiscoveryDocument(JsonFactory jsonFactory, HttpTransport httpTransport)
      throws IOException {
    HttpRequestFactory requestFactory =
        httpTransport.createRequestFactory(
            request -> {
              request.setParser(jsonFactory.createJsonObjectParser());
            });
    GenericUrl wellKnownConfig = new GenericUrl(issuer);
    wellKnownConfig.appendRawPath(WELL_KNOWN_CONFIG);
    HttpRequest request = requestFactory.buildGetRequest(wellKnownConfig);
    return request.execute().parseAs(OIDCEndpoints.class);
  }

  /** Internal. */
  public static class OIDCEndpoints extends GenericJson {
    @Key("authorization_endpoint")
    private String authEndpoint;

    @Key("token_endpoint")
    private String tokenEndpoint;

    @Key("jwks_uri")
    private String jwksUri;

    public String getAuthEndpoint() {
      return authEndpoint;
    }

    public String getTokenEndpoint() {
      return tokenEndpoint;
    }

    public String getJwksUri() {
      return jwksUri;
    }
  }

  /** A token from a provider with both openid and email scope claims. */
  public static class EmailIdToken {
    private final String emailAddress;
    private final String idToken;

    private EmailIdToken(String emailAddress, String idToken) {
      this.emailAddress = emailAddress;
      this.idToken = idToken;
    }

    /** The email address claim from the token. */
    public String getEmailAddress() {
      return emailAddress;
    }

    /** The full oauth token obtained from the provider. */
    public String getIdToken() {
      return idToken;
    }
  }

  /** Interface for allowing custom browser handlers for OauthClients. */
  @FunctionalInterface
  public interface BrowserHandler {
    /** Opens a browser to allow a user to complete the oauth browser workflow. */
    void openBrowser(String url) throws IOException;
  }
}
