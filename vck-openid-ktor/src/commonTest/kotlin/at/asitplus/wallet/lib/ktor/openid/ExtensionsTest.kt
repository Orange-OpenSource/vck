package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headers
import io.ktor.http.headersOf

val ExtensionsTest by testSuite {

    suspend fun buildResponse(
        status: HttpStatusCode,
        body: String,
        headers: Headers = headersOf(),
    ) : io.ktor.client.statement.HttpResponse {
        val client = HttpClient(MockEngine { respond(body, status = status, headers = headers) })
        return try {
            client.get("https://example.com")
        } finally {
            client.close()
        }
    }

    test("onFailure returns failure with OAuth2Error") {
        val expectedError = OAuth2Error(error = "invalid_client", errorDescription = "Nope")
        val response = buildResponse(
            status = HttpStatusCode.BadRequest,
            body = vckJsonSerializer.encodeToString(OAuth2Error.serializer(), expectedError),
            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        )

        val result = response.onFailure { error, _ -> error }

        val failure = result.shouldBeInstanceOf<IntermediateResult.Failure<OAuth2Error?>>()
        failure.result shouldBe expectedError
    }

    test("onSuccess unwraps response body") {
        val response = buildResponse(
            status = HttpStatusCode.OK,
            body = "expected-body",
            headers = headersOf(HttpHeaders.ContentType, ContentType.Text.Plain.toString())
        )

        val intermediate = response.onFailure { "failure" }
        val body = intermediate.onSuccess<String, String> { this }

        body shouldBe "expected-body"
    }

    test("dpopNonce extracts nonce from error or WWW-Authenticate") {
        val authServerNonce = "nonce-auth"
        val authServerResponse = buildResponse(
            status = HttpStatusCode.BadRequest,
            body = vckJsonSerializer.encodeToString(OAuth2Error.serializer(), OAuth2Error(error = USE_DPOP_NONCE)),
            headers = headers {
                append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                append(HttpHeaders.DPoPNonce, authServerNonce)
            }
        )

        OAuth2Error(error = USE_DPOP_NONCE).dpopNonce(authServerResponse) shouldBe authServerNonce

        val resourceServerNonce = "nonce-resource"
        val resourceServerResponse = buildResponse(
            status = HttpStatusCode.Unauthorized,
            body = "",
            headers = headers {
                append(HttpHeaders.WWWAuthenticate, "Bearer error=\"$USE_DPOP_NONCE\"")
                append(HttpHeaders.DPoPNonce, resourceServerNonce)
            }
        )

        null.dpopNonce(resourceServerResponse) shouldBe resourceServerNonce
    }
}
