/*
 * Copyright 2023 Curity AB
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

package io.curity.identityserver.plugins.authenticator.authentication

import io.curity.identityserver.plugins.authenticator.config.ShortKeyOidcAuthenticatorPluginConfig
import org.jose4j.http.SimpleGet
import org.jose4j.http.SimpleResponse
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jwt.consumer.JwtConsumer
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.plugin.ManagedObject
import se.curity.identityserver.sdk.service.HttpClient
import java.net.URI

class ProviderConfigurationManagedObject(private val _config: ShortKeyOidcAuthenticatorPluginConfig) :
    ManagedObject<ShortKeyOidcAuthenticatorPluginConfig>(_config) {
    companion object {
        private val _logger: Logger = LoggerFactory.getLogger(ShortKeyOidcAuthenticatorPluginConfig::class.java)
    }

    private var metadata: DiscoveredProviderMetadata? = null

    lateinit var tokenEndpoint: URI

    lateinit var authorizeEndpoint: URI

    private lateinit var _httpClient: HttpClient

    val jwtConsumer: JwtConsumer by lazy { createJwtConsumer() }

    /**
     * Since the http client is not available until runtime,
     * the request handlers will have to prepare the object with the HTTP client to use.
     *
     * @param httpClient from configuration
     */
    fun prepare(httpClient: HttpClient) = run {
        if (metadata != null) {
            return
        }
        _httpClient = httpClient
        metadata = DiscoveredProviderMetadata(_config, httpClient)
        authorizeEndpoint = metadata?.authorizeEndpoint ?: throw _config.getExceptionFactory()
            .internalServerException(ErrorCode.PLUGIN_ERROR, "Metadata not fetched")
        tokenEndpoint = metadata?.tokenEndpoint ?: throw _config.getExceptionFactory()
            .internalServerException(ErrorCode.PLUGIN_ERROR, "Metadata not fetched")
    }

    private fun createJwtConsumer(): JwtConsumer {
        val jwksUri = metadata?.jwksUri ?: throw _config.getExceptionFactory()
            .internalServerException(ErrorCode.PLUGIN_ERROR, "Metadata not fetched")
        _logger.info("jwks_uri: $jwksUri")

        val httpsJwks = HttpsJwks(jwksUri)
        httpsJwks.setSimpleHttpGet(SimpleGet { location: String ->
            try {
                val response = _httpClient.request(URI(location))
                    .accept("application/json")
                    .get().response()
                return@SimpleGet SimpleResponseAdapter(response)
            } catch (e: Exception) {
                throw _config.getExceptionFactory()
                    .internalServerException(ErrorCode.PLUGIN_ERROR, "Could not fetch JWKS")
            }
        })

        return JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setSkipDefaultAudienceValidation()
            .setExpectedIssuer(_config.getIssuer())
            .setRelaxVerificationKeyValidation()
            .setVerificationKeyResolver(HttpsJwksVerificationKeyResolver(httpsJwks))
            .build()
    }

    /**
     * Used to be able to use the SDK HttpClient with the Jose4j library, to keep the http settings in Curity config
     */
    class SimpleResponseAdapter(response: HttpResponse) : SimpleResponse {
        private val statusCode = response.statusCode()
        private val statusMessage = response.toString()
        private val headers = response.headers()
        private val body = response.body(HttpResponse.asString())

        override fun getStatusCode(): Int = statusCode

        override fun getStatusMessage(): String = statusMessage

        override fun getHeaderNames(): MutableCollection<String> = headers.map().keys

        override fun getHeaderValues(headerName: String): MutableList<String> = headers.allValues(headerName)

        override fun getBody(): String = body
    }

    /**
     * Disccovers and holds the metadata of the OpenID provider
     */
    class DiscoveredProviderMetadata(config: ShortKeyOidcAuthenticatorPluginConfig, httpClient: HttpClient) {
        companion object {
            private val _logger: Logger = LoggerFactory.getLogger(DiscoveredProviderMetadata::class.java)
        }

        private val _exceptionFactory = config.getExceptionFactory()

        val tokenEndpoint: URI
        val authorizeEndpoint: URI
        val jwksUri: String

        init {
            _logger.info("Discovering metadata")
            val discoveryResponse = httpClient
                .request(URI(config.getIssuer() + "/.well-known/openid-configuration"))
                .header("Accept", "application/json")
                .get().response()
            val providerConfiguration = discoveryResponse.body(HttpResponse.asJsonObject(config.getJson()))

            jwksUri = providerConfiguration["jwks_uri"] as String? ?: throw _exceptionFactory
                .configurationException("Could not get jwks_uri from provider metadata")

            val authorization = providerConfiguration["authorization_endpoint"] as String? ?: throw _exceptionFactory
                .configurationException("Could not get authorization_endpoint from provider metadata")
            authorizeEndpoint = URI(authorization)

            val token = providerConfiguration["token_endpoint"] as String? ?: throw _exceptionFactory
                .configurationException("Could not get token_endpoint from provider metadata")
            tokenEndpoint = URI(token)
        }

    }
}
