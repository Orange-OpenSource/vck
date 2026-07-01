package at.asitplus.wallet.lib

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.IssuerSignedListSerializer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import com.benasher44.uuid.uuid4
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

@Suppress("DEPRECATION")
private data class DeprecatedTestCredentialScheme(
    override val vcType: String? = null,
    override val sdJwtType: String? = null,
    override val isoNamespace: String? = null,
    override val isoDocType: String? = null,
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT),
) : ConstantIndex.CredentialScheme

private data class TestCredentialScheme(
    override val vcType: String? = null,
    override val sdJwtType: String? = null,
    override val isoNamespace: String? = null,
    override val isoDocType: String? = null,
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT),
) : CredentialScheme

val LibraryInitializerTest by matrixSuite {
    "registerExtensionLibrary registers schemes without serializer modules" {
        val deprecatedScheme = DeprecatedTestCredentialScheme(
            vcType = "TestCredential-${uuid4()}",
        )
        val scheme = TestCredentialScheme(
            vcType = "TestCredential-${uuid4()}",
        )

        @Suppress("DEPRECATION")
        LibraryInitializer.registerExtensionLibrary(deprecatedScheme)
        LibraryInitializer.registerExtensionLibrary(scheme)

        AttributeIndex.resolveAttributeType(deprecatedScheme.vcType!!) shouldBe deprecatedScheme
        AttributeIndex.resolveAttributeType(scheme.vcType!!) shouldBe scheme
    }

    "registerExtensionLibrary registers ISO encoders and serializers (deprecated)" {
        @Serializable
        data class MockIssuerSignedValue(val value: String)

        val elementId = "element-${uuid4()}"
        val isoNamespace = "namespace.${uuid4()}"
        val deprecatedScheme = DeprecatedTestCredentialScheme(
            vcType = "IsoCredential-${uuid4()}",
            isoNamespace = isoNamespace,
            isoDocType = "doctype.${uuid4()}",
            supportedRepresentations = listOf(ISO_MDOC),
        )
        val scheme = DeprecatedTestCredentialScheme(
            vcType = "IsoCredential-${uuid4()}",
            isoNamespace = isoNamespace,
            isoDocType = "doctype.${uuid4()}",
            supportedRepresentations = listOf(ISO_MDOC),
        )

        LibraryInitializer.registerExtensionLibrary(
            deprecatedScheme,
            jsonValueEncoder = { value: Any ->
                when (value) {
                    is MockIssuerSignedValue -> joseCompliantSerializer.encodeToJsonElement<MockIssuerSignedValue>(value)
                    else -> null
                }
            },
            itemValueSerializerMap = mapOf<String, KSerializer<MockIssuerSignedValue>>(
                elementId to MockIssuerSignedValue.serializer()
            ),
        )

        JsonCredentialSerializer.encode(MockIssuerSignedValue("encoded")) shouldBe
                joseCompliantSerializer.encodeToJsonElement(MockIssuerSignedValue("encoded"))

        val list = IssuerSignedList(
            listOf(
                ByteStringWrapper(
                    IssuerSignedItem(
                        digestId = 1u,
                        random = Random.nextBytes(16),
                        elementIdentifier = elementId,
                        elementValue = MockIssuerSignedValue("round-trip"),
                    )
                )
            )
        )
        val encodedList = coseCompliantSerializer.encodeToByteArray(
            IssuerSignedListSerializer(isoNamespace),
            list
        )
        val decodedList = coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedListSerializer(isoNamespace),
            encodedList
        )
        decodedList shouldBe list
    }

    "registerExtensionLibrary registers ISO encoders and serializers" {
        @Serializable
        data class MockIssuerSignedValue(val value: String)

        val elementId = "element-${uuid4()}"
        val isoNamespace = "namespace.${uuid4()}"
        val scheme = DeprecatedTestCredentialScheme(
            vcType = "IsoCredential-${uuid4()}",
            isoNamespace = isoNamespace,
            isoDocType = "doctype.${uuid4()}",
            supportedRepresentations = listOf(ISO_MDOC),
        )

        LibraryInitializer.registerExtensionLibrary(
            scheme,
            jsonValueEncoder = { value: Any ->
                when (value) {
                    is MockIssuerSignedValue -> joseCompliantSerializer.encodeToJsonElement<MockIssuerSignedValue>(value)
                    else -> null
                }
            },
            itemValueSerializerMap = mapOf<String, KSerializer<MockIssuerSignedValue>>(
                elementId to MockIssuerSignedValue.serializer()
            ),
        )

        JsonCredentialSerializer.encode(MockIssuerSignedValue("encoded")) shouldBe
                joseCompliantSerializer.encodeToJsonElement(MockIssuerSignedValue("encoded"))

        val list = IssuerSignedList(
            listOf(
                ByteStringWrapper(
                    IssuerSignedItem(
                        digestId = 1u,
                        random = Random.nextBytes(16),
                        elementIdentifier = elementId,
                        elementValue = MockIssuerSignedValue("round-trip"),
                    )
                )
            )
        )
        val encodedList = coseCompliantSerializer.encodeToByteArray(
            IssuerSignedListSerializer(isoNamespace),
            list
        )
        val decodedList = coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedListSerializer(isoNamespace),
            encodedList
        )
        decodedList shouldBe list
    }
}
