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
import org.slf4j.Marker
import org.slf4j.MarkerFactory
import se.curity.identityserver.sdk.attribute.*
import se.curity.identityserver.sdk.authentication.AuthenticationResult
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.http.ContentType
import se.curity.identityserver.sdk.http.HttpRequest
import se.curity.identityserver.sdk.http.HttpResponse
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import java.util.*


class CallbackRequestHandler(
    private val _config: ShortKeyOidcAuthenticatorPluginConfig,
    private val _providerConfiguration: ProviderConfigurationManagedObject
) : AuthenticatorRequestHandler<CallbackRequestModel> {
    private val _exceptionFactory: ExceptionFactory = _config.getExceptionFactory()
    private val _authenticatorInformationProvider: AuthenticatorInformationProvider =
        _config.getAuthenticatorInformationProvider()

    companion object {
        private val _logger: Logger = LoggerFactory.getLogger(CallbackRequestHandler::class.java)
        private val MASK_MARKER: Marker = MarkerFactory.getMarker("MASK")

        private val FILTER_CLAIMS = listOf("sub", "iat", "exp", "amr", "acr", "azp", "auth_time", "iss", "aud")
    }

    override fun preProcess(request: Request, response: Response): CallbackRequestModel {
        if (request.isGetRequest) {
            _providerConfiguration.prepare(_config.getHttpClient())
            return CallbackRequestModel(request)
        } else {
            throw _exceptionFactory.methodNotAllowed()
        }
    }

    override fun post(requestModel: CallbackRequestModel, response: Response): Optional<AuthenticationResult> =
        throw _exceptionFactory.methodNotAllowed()

    override fun get(requestModel: CallbackRequestModel, response: Response): Optional<AuthenticationResult> {
        if (requestModel.isError()) {
            handleErrorAndThrow(requestModel)
        }

        validateState(requestModel.state)

        val tokenResponseData = redeemCodeForTokens(requestModel)
        _logger.debug(MASK_MARKER, "ID token: " + tokenResponseData["id_token"])

        val idTokenClaims =
            _providerConfiguration.jwtConsumer.processToClaims(tokenResponseData["id_token"] as String)

        val subjectAttributes =
            idTokenClaims.claimsMap.filter { entry -> !FILTER_CLAIMS.contains(entry.key) }.toMutableMap()
        subjectAttributes["subject"] = idTokenClaims.subject

        val attributes = AuthenticationAttributes.of(
            SubjectAttributes.of(subjectAttributes),
            ContextAttributes.of(
                Attributes.of(
                    Attribute.of(
                        "provider_access_token",
                        tokenResponseData["access_token"] as String
                    )
                )
            )
        )

        return Optional.ofNullable(AuthenticationResult(attributes))
    }

    private fun redeemCodeForTokens(requestModel: CallbackRequestModel): Map<String, Any> {
        val redirectUri = createRedirectUri(_authenticatorInformationProvider, _exceptionFactory)

        val tokenResponse = _config.getHttpClient()
            .request(_providerConfiguration.tokenEndpoint)
            .contentType(ContentType.X_WWW_FORM_URLENCODED.contentType)
            .body(HttpRequest.createFormUrlEncodedBodyProcessor(createPostData(requestModel.code, redirectUri)))
            .post()
            .response()

        when (tokenResponse.statusCode()) {
            200 -> return tokenResponse.body(HttpResponse.asJsonObject(_config.getJson()))
            else -> {
                if (_logger.isInfoEnabled) {
                    _logger.info(
                        "Got error response from token endpoint: error = {}, {}", tokenResponse.statusCode(),
                        tokenResponse.body(HttpResponse.asString())
                    )
                }
                throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR)
            }
        }
    }

    private fun handleErrorAndThrow(requestModel: CallbackRequestModel) {
        _logger.info(
            "User authentication failed. error: {}, error_description: {}",
            requestModel.error,
            requestModel.errorDescription
        )
        throw _exceptionFactory.unauthorizedException(ErrorCode.AUTHENTICATION_FAILED, "User authentication failed")
    }

    private fun createPostData(
        code: String,
        callbackUri: String
    ): Map<String, String> = hashMapOf(
        "code" to code,
        "grant_type" to "authorization_code",
        "redirect_uri" to callbackUri
    )

    private fun validateState(state: String) {
        val sessionAttribute: Attribute? = _config.getSessionManager().get("state")

        if (state == sessionAttribute?.getValueOfType(String::class.java)) {
            _logger.debug("State matches session")
        } else {
            _logger.debug("State did not match session")

            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_INPUT, "Bad state provided")
        }
    }
}
