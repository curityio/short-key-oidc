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

import io.curity.identityserver.plugins.authenticator.authentication.RedirectUriUtil.Companion.createRedirectUri
import io.curity.identityserver.plugins.authenticator.config.ShortKeyOidcAuthenticatorPluginConfig
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.http.RedirectStatusCode
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.util.Optional
import java.util.UUID

class ShortKeyOidcAuthenticatorRequestHandler(private val _config: ShortKeyOidcAuthenticatorPluginConfig,
                                              private val _providerConfig : ProviderConfigurationManagedObject) :
    AuthenticatorRequestHandler<Request> {
    private val _authenticatorInformationProvider: AuthenticatorInformationProvider =
        _config.getAuthenticatorInformationProvider()
    private val _exceptionFactory: ExceptionFactory = _config.getExceptionFactory()

    override fun get(request: Request, response: Response): Optional<AuthenticationResult> {
        _logger.debug("GET request received for authentication")

        val redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory)
        val state = UUID.randomUUID().toString()
        val scope = _config.getScope().toMutableSet().apply {
            if ("openid" !in this) {
                _logger.debug("Configured scope did not contain 'openid', adding it to the request")
                add("openid")
            }
        }

        _config.getSessionManager().put(Attribute.of("state", state))

        val queryStringArguments = linkedMapOf<String, Collection<String>>(
            "client_id" to setOf(_config.getClientId()),
            "redirect_uri" to setOf(redirectUri),
            "state" to setOf(state),
            "response_type" to setOf("code"),
            "scope" to setOf(scope.joinToString(" "))
        )

        _logger.debug("Redirecting to {} with query string arguments {}", _providerConfig.authorizeEndpoint,
            queryStringArguments
        )

        throw _exceptionFactory.redirectException(
            _providerConfig.authorizeEndpoint,
            RedirectStatusCode.MOVED_TEMPORARILY, queryStringArguments, false
        )
    }

    override fun post(request: Request, response: Response): Optional<AuthenticationResult> {
        throw _exceptionFactory.methodNotAllowed()
    }

    override fun preProcess(request: Request, response: Response): Request {
        _providerConfig.prepare(_config.getHttpClient())
        return request
    }

    companion object {
        private val _logger: Logger = LoggerFactory.getLogger(ShortKeyOidcAuthenticatorRequestHandler::class.java)
    }
}
