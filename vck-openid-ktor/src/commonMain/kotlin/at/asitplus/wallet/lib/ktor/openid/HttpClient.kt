package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.header
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.serialization.kotlinx.json.json

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
}
