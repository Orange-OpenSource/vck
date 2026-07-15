package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.HttpResponseValidator
import io.ktor.client.plugins.ResponseException
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

data class ProblemDetails(
    val type: String = "about:blank",
    val status: Int? = null,
    val title: String? = null,
    val detail: String? = null,
    val instance: String? = null,
    val extensions: JsonObject = JsonObject(emptyMap()),
)

class HttpErrorResponseException(
    response: HttpResponse,
    val responseBody: String,
    val oauth2Error: OAuth2Error?,
    val problemDetails: ProblemDetails?,
) : ResponseException(response, responseBody) {
    override val message = oauth2Error?.errorDescription
        ?: oauth2Error?.error
        ?: problemDetails?.detail
        ?: problemDetails?.title
        ?: responseBody.takeIf { it.isNotBlank() }
        ?: "HTTP ${response.status}"
}

internal fun buildHttpClient(
    engine: HttpClientEngine,
    cookiesStorage: CookiesStorage? = null,
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
) = HttpClient(engine) {
    followRedirects = false
    install(ContentNegotiation) {
        json(joseCompliantSerializer)
    }
    install(DefaultRequest) {
        header(HttpHeaders.ContentType, ContentType.Application.Json)
    }
    httpClientConfig?.let { apply(it) }
    cookiesStorage?.let {
        install(HttpCookies) {
            storage = it
        }
    }
    installResponseValidation()
}

private fun HttpClientConfig<*>.installResponseValidation() {
    expectSuccess = true
    HttpResponseValidator {
        handleResponseExceptionWithRequest { cause, _ ->
            val response = (cause as? ResponseException)?.response
                ?: return@handleResponseExceptionWithRequest
            val body = response.bodyAsText()
            val json = catchingUnwrapped {
                joseCompliantSerializer.parseToJsonElement(body).jsonObject
            }.getOrNull()

            throw HttpErrorResponseException(
                response = response,
                responseBody = body,
                oauth2Error = json?.let {
                    catchingUnwrapped {
                        joseCompliantSerializer.decodeFromJsonElement(OAuth2Error.serializer(), it)
                    }.getOrNull()
                },
                problemDetails = json?.takeIf {
                    response.contentType()?.withoutParameters() == ContentType.Application.ProblemJson
                }?.toProblemDetails(),
            )
        }
    }
}

private val problemDetailsMembers = setOf("type", "title", "status", "detail", "instance")

private fun JsonObject.toProblemDetails() = ProblemDetails(
    type = string("type") ?: "about:blank",
    status = (get("status") as? JsonPrimitive)
        ?.takeUnless { it.isString }
        ?.intOrNull
        ?.takeIf { it in 100..599 },
    title = string("title"),
    detail = string("detail"),
    instance = string("instance"),
    extensions = JsonObject(filterKeys { it !in problemDetailsMembers }),
)

private fun JsonObject.string(name: String) = (get(name) as? JsonPrimitive)
    ?.takeIf { it.isString }
    ?.contentOrNull
