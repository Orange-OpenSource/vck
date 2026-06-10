package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.FixedTimeClock
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialMetadataLookup
import at.asitplus.wallet.sdjwt.SdJwtVcType
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf

val RemoteCredentialMetadataRegistryTest by testSuite {

    "findEntry fetches aliased remote metadata" {
        val vct = SdJwtVcType("urn:test:remote:${uuid4()}")
        val vcType = "RemoteTestCredential-${uuid4()}"
        val metadataUrl = "https://metadata.example.test/${uuid4()}/type-metadata.json"
        var requestedUrl: String? = null

        val httpClient = HttpClient(MockEngine { request ->
            requestedUrl = request.url.toString()
            respond(
                content = """
                    {
                      "vct": "${vct.string}",
                      "vck": {
                        "format": "jwt_vc_json",
                        "vcType": "$vcType"
                      }
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.CacheControl, "max-age=60")
            )
        })

        try {
            val registry = RemoteCredentialMetadataRegistry(
                httpClient = httpClient,
                clock = FixedTimeClock(0),
                documentUrls = mutableMapOf(vct to metadataUrl),
                aliases = mapOf(CredentialMetadataLookup(PLAIN_JWT, vcType) to vct),
            )

            val entry = registry.findEntry(vcType, PLAIN_JWT).shouldNotBeNull()

            requestedUrl shouldBe metadataUrl
            entry.loadedFrom shouldBe metadataUrl
            entry.metadata.vct shouldBe vct
            entry.metadata.vckExtensions?.vcType shouldBe vcType
            entry.aliases shouldContain vcType
        } finally {
            httpClient.close()
        }
    }
}
