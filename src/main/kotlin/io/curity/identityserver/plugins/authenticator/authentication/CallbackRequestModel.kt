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

import se.curity.identityserver.sdk.web.Request

class CallbackRequestModel(request: Request)
{
    val error: String? = request.getQueryParameterValueOrError("error", invalidParameter)
    val errorDescription: String? = request.getQueryParameterValueOrError("error_description", invalidParameter)
    val code: String = request.getQueryParameterValueOrError("code", invalidParameter)
    val state: String = request.getQueryParameterValueOrError("state", invalidParameter)

    fun isError() = error != null|| errorDescription != null

    companion object
    {
        private val invalidParameter = { s: String -> RuntimeException(String.format(
                "Expected only one query string parameter named %s, but found multiple.", s)) }
    }
}
