package at.asitplus.wallet.lib.data

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.sdjwt.CredentialFormatEnum
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRegistry
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataVckExtensions
import at.asitplus.wallet.sdjwt.SdJwtVcType
import at.asitplus.wallet.sdjwt.W3cSubresourceIntegrityMetadata
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

val StaticCredentialMetadataRegistryTest by matrixSuite {

    "static registry resolves SD-JWT metadata through AttributeIndex" {
        val vct = SdJwtVcType("urn:test:sd-jwt:${uuid4()}")
        val loadedFrom = "https://metadata.example.test/${uuid4()}/sd-jwt.json"
        LibraryInitializer.registerCredentialMetadataRegistry(
            StaticCredentialMetadataRegistry(
                documentRegistry = SdJwtTypeMetadataDocumentRegistry(vct to metadataDocument(vct)),
                documentUrls = mapOf(vct to loadedFrom),
            )
        )

        AttributeIndex.resolveSdJwtAttributeType(vct.string).shouldNotBeNull().apply {
            schemaUri shouldBe loadedFrom
            sdJwtType shouldBe vct.string
        }

        AttributeIndex.resolveIdentifier(vct.string, SD_JWT).apply {
            schemaUri shouldBe loadedFrom
            sdJwtType shouldBe vct.string
        }
    }

    "preload defers integrity-pinned entries to the checked findEntry path" {
        val vct = SdJwtVcType("urn:test:sd-jwt:${uuid4()}")
        val loadedFrom = "https://metadata.example.test/${uuid4()}/sd-jwt.json"
        val registry = StaticCredentialMetadataRegistry(
            documentRegistry = SdJwtTypeMetadataDocumentRegistry(vct to metadataDocument(vct)),
            documentUrls = mapOf(vct to loadedFrom),
            integrityMetadata = mapOf(
                vct to W3cSubresourceIntegrityMetadata(
                    "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
                )
            ),
        )
        // Not eagerly preloaded: the integrity check is suspending, so an unchecked entry must not pass synchronously.
        registry.preloadEntries().shouldBeEmpty()
    }

    "static registry resolves W3C JWT metadata through AttributeIndex" {
        val vct = SdJwtVcType("urn:test:w3c:${uuid4()}")
        val vcType = "TestW3cCredential-${uuid4()}"
        val loadedFrom = "https://metadata.example.test/${uuid4()}/w3c.json"
        LibraryInitializer.registerCredentialMetadataRegistry(
            StaticCredentialMetadataRegistry(
                documentRegistry = SdJwtTypeMetadataDocumentRegistry(
                    vct to metadataDocument(
                        vct = vct,
                        vckExtensions = SdJwtTypeMetadataVckExtensions(
                            format = CredentialFormatEnum.JWT_VC,
                            vcType = vcType,
                        ),
                    )
                ),
                documentUrls = mapOf(vct to loadedFrom),
            )
        )

        AttributeIndex.resolveAttributeType(vcType).shouldNotBeNull().apply {
            schemaUri shouldBe loadedFrom
            this.vcType shouldBe vcType
        }

        AttributeIndex.resolveIdentifierPlainJwt(listOf("VerifiableCredential", vcType)).apply {
            schemaUri shouldBe loadedFrom
            this.vcType shouldBe vcType
        }
    }

    "static registry resolves ISO mDoc metadata through AttributeIndex" {
        val vct = SdJwtVcType("urn:test:iso:${uuid4()}")
        val docType = "org.example.${uuid4()}.credential"
        val namespace = "org.example.${uuid4()}"
        val loadedFrom = "https://metadata.example.test/${uuid4()}/iso.json"
        val registry = StaticCredentialMetadataRegistry(
            documentRegistry = SdJwtTypeMetadataDocumentRegistry(
                vct to metadataDocument(
                    vct = vct,
                    vckExtensions = SdJwtTypeMetadataVckExtensions(
                        format = CredentialFormatEnum.MSO_MDOC,
                        isoDocType = docType,
                        isoNamespace = namespace,
                    ),
                )
            ),
            documentUrls = mapOf(vct to loadedFrom),
        )
        registry.findEntry(docType, ISO_MDOC).shouldNotBeNull()
        LibraryInitializer.registerCredentialMetadataRegistry(
            registry
        )

        AttributeIndex.resolveIsoDoctype(docType).shouldNotBeNull().apply {
            schemaUri shouldBe loadedFrom
            isoDocType shouldBe docType
            isoNamespace shouldBe namespace
        }

        AttributeIndex.resolveIdentifier(docType, ISO_MDOC).apply {
            schemaUri shouldBe loadedFrom
            isoDocType shouldBe docType
            isoNamespace shouldBe namespace
        }
    }
}

private fun metadataDocument(
    vct: SdJwtVcType,
    vckExtensions: SdJwtTypeMetadataVckExtensions? = null,
) = SdJwtTypeMetadataDocument(
    originalBytes = ByteArray(0),
    definition = SdJwtTypeMetadataDefinition(
        vct = vct,
        vckExtensions = vckExtensions,
    ),
)
