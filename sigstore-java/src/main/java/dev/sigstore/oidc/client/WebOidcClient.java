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
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Key;
import com.google.api.client.util.Preconditions;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import dev.sigstore.forbidden.SuppressForbidden;
import dev.sigstore.http.HttpClients;
import dev.sigstore.http.HttpParams;
import dev.sigstore.trustroot.Service;
import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;

/**
 * A client to obtain oidc tokens from an oauth provider via web workflow for use with sigstore. By
 * default this client is configued to use the public sigstore dex instance.
 */
public class WebOidcClient implements OidcClient {
  private static final Logger log = Logger.getLogger(WebOidcClient.class.getName());

  private static final String ID_TOKEN_KEY = "id_token";
  private static final String DEFAULT_CLIENT_ID = "sigstore";
  private static final String WELL_KNOWN_CONFIG = "/.well-known/openid-configuration";

  private final HttpParams httpParams;
  private final String clientId;
  private final String issuer;
  private final BrowserHandler browserHandler;

  private WebOidcClient(
      HttpParams httpParams, String issuer, String clientId, BrowserHandler browserHandler) {
    this.httpParams = httpParams;
    this.clientId = clientId;
    this.issuer = issuer;
    this.browserHandler = browserHandler;
  }

  public static WebOidcClient.Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private HttpParams httpParams = HttpParams.builder().build();
    private String clientId = DEFAULT_CLIENT_ID;
    private Service issuer;
    private BrowserHandler browserHandler = null;

    private Builder() {}

    /** Configure the http properties, see {@link HttpParams} */
    public Builder setHttpParams(HttpParams httpParams) {
      this.httpParams = httpParams;
      return this;
    }

    /** The client id used in the oidc request, defaults to {@value DEFAULT_CLIENT_ID}. */
    public Builder setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /** The issuer of the oidc tokens (the oidc service). */
    public Builder setIssuer(Service issuer) {
      this.issuer = issuer;
      return this;
    }

    /** Deprecated compat issuer selector, remove in next version. */
    @Deprecated
    public Builder setIssuer(String issuer) {
      this.issuer = Service.of(URI.create(issuer), 1);
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

    public WebOidcClient build() {
      Preconditions.checkNotNull(issuer);
      BrowserHandler bh =
          browserHandler != null
              ? browserHandler
              : new AuthorizationCodeInstalledApp.DefaultBrowser()::browse;
      return new WebOidcClient(httpParams, issuer.getUrl().toString(), clientId, bh);
    }
  }

  /** This provider is usually enabled unless we're in CI. */
  @Override
  public boolean isEnabled(Map<String, String> env) {
    if ("true".equalsIgnoreCase(env.get("CI"))) {
      log.info("Skipping browser based oidc provider because CI detected");
      return false;
    }
    return true;
  }

  /**
   * Get an id token from the oidc provider with openid and email scopes
   *
   * @return an openid token with additional email scopes
   * @throws OidcException if an error occurs doing the authorization flow
   */
  @Override
  @SuppressForbidden(reason = "HttpClients#newHttpTransport(HttpParams)")
  public OidcToken getIDToken(Map<String, String> env) throws OidcException {
    JsonFactory jsonFactory = new GsonFactory();
    HttpTransport httpTransport = HttpClients.newHttpTransport(httpParams);
    DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();
    OIDCEndpoints endpoints;
    try {
      endpoints = parseDiscoveryDocument(jsonFactory);
    } catch (IOException e) {
      // TODO: maybe a more descriptive exception message
      throw new OidcException(
          "ioexception obtaining and parsing oidc configuration for " + issuer, e);
    }

    // Generate a cryptographically secure nonce for replay attack prevention
    String nonce = generateNonce();

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
            .setRequestInitializer(
                (req) -> req.getHeaders().set("User-Agent", httpParams.getUserAgent()))
            .setCredentialCreatedListener(
                (credential, tokenResponse) ->
                    memStoreFactory
                        .getDataStore("user")
                        .set(ID_TOKEN_KEY, tokenResponse.get(ID_TOKEN_KEY).toString()));

    // Use custom flow that injects nonce into authorization URL
    NonceAuthorizationCodeFlow flow = new NonceAuthorizationCodeFlow(flowBuilder, nonce);
    AuthorizationCodeInstalledApp app =
        new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver(), browserHandler::openBrowser);

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
      if (!idTokenVerifier.verifyOrThrow(parsedIdToken)) {
        throw new OidcException("id token could not be verified");
      }

      // Verify that the nonce in the ID token matches the one we sent
      Object tokenNonce = parsedIdToken.getPayload().get("nonce");
      if (tokenNonce == null) {
        throw new OidcException("id token is missing required nonce claim");
      }
      if (!nonce.equals(tokenNonce.toString())) {
        throw new OidcException(
            "nonce in id token does not match expected value - possible replay attack");
      }
    } catch (IOException e) {
      // TODO: maybe a more descriptive exception message
      throw new OidcException("ioexception during oidc handshake", e);
    }

    String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
    boolean emailVerified = (boolean) parsedIdToken.getPayload().get("email_verified");
    if (Boolean.FALSE.equals(emailVerified)) {
      throw new OidcException(
          String.format(
              Locale.ROOT,
              "identity provider '%s' reports email address '%s' has not been verified",
              parsedIdToken.getPayload().getIssuer(),
              emailFromIDToken));
    }

    return ImmutableOidcToken.builder()
        .subjectAlternativeName(emailFromIDToken)
        .idToken(idTokenString)
        .issuer(issuer)
        .build();
  }

  // Parses an oidc discovery document to discover other endpoints. This method does not
  // parse all the values, only the endpoints we care about.
  OIDCEndpoints parseDiscoveryDocument(JsonFactory jsonFactory) throws IOException {
    var requestFactory =
        HttpClients.newRequestFactory(
            HttpParams.builder().build(), jsonFactory.createJsonObjectParser());
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

  /** Interface for allowing custom browser handlers for OauthClients. */
  @FunctionalInterface
  public interface BrowserHandler {
    /** Opens a browser to allow a user to complete the oauth browser workflow. */
    void openBrowser(String url) throws IOException;
  }

  /**
   * Generates a cryptographically secure random nonce for OIDC authentication. The nonce is used to
   * prevent replay attacks by binding the ID token to the authentication request.
   *
   * @return a URL-safe base64-encoded random string
   */
  private static String generateNonce() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] nonceBytes = new byte[32];
    secureRandom.nextBytes(nonceBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
  }

  /**
   * Custom AuthorizationCodeFlow that adds a nonce parameter to the authorization URL. This is
   * required for OpenID Connect to prevent replay attacks.
   */
  private static class NonceAuthorizationCodeFlow extends AuthorizationCodeFlow {
    private final String nonce;

    NonceAuthorizationCodeFlow(AuthorizationCodeFlow.Builder builder, String nonce) {
      super(builder);
      this.nonce = nonce;
    }

    @Override
    public AuthorizationCodeRequestUrl newAuthorizationUrl() {
      return super.newAuthorizationUrl().set("nonce", nonce);
    }

    String getNonce() {
      return nonce;
    }
  }
}
