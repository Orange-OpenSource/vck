package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.dcapi.EncryptedResponseData
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.authTag
import at.asitplus.signum.indispensable.symmetric.keyFrom
import at.asitplus.signum.indispensable.symmetric.nonce
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

/**
 * Tests [DcApiVerifier] against a simulated wallet performing an ISO/IEC 18013-7 Annex C
 * presentation over the Digital Credentials API, analogous to [OpenId4VpDcApiProtocolTest].
 */
val Iso180137AnnexCProtocolTest by matrixSuite {

    val callingOrigin = "https://example.com"

    val requestedCredential = RequestOptionsCredential(
        credentialScheme = AtomicAttribute2023,
        representation = ISO_MDOC,
        attributePaths = setOf(
            DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
            DCQLClaimsPathPointer(CLAIM_DATE_OF_BIRTH),
        ),
    )
    val dcqlRequest = CredentialPresentationRequestBuilder(requestedCredential).toDCQLRequest()!!

    fixture({
        kotlinx.coroutines.runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also { agent ->
                agent.storeCredential(
                    IssuerAgent(
                        keyMaterial = EphemeralKeyWithSelfSignedCert(),
                        identifier = "https://issuer.example.com/".toUri(),
                        randomSource = RandomSource.Default,
                    ).issueCredential(
                        DummyCredentialDataProvider.getCredential(
                            holderKeyMaterial.publicKey,
                            AtomicAttribute2023,
                            ISO_MDOC,
                        ).getOrThrow()
                    ).getOrThrow().toStoreCredentialInput()
                ).getOrThrow()
            }
            object {
                val decryptionKeyMaterial = EphemeralKeyWithoutCert()
                val stateToIsoMdocRequestStore = DefaultMapStore<String, IsoMdocRequest>()
                val verifier = DcApiVerifier(
                    clientIdScheme = ClientIdScheme.PreRegistered(
                        clientId = "dc-api-rp-${uuid4()}",
                        redirectUri = "https://example.com/callback",
                    ),
                    stateToIsoMdocRequestStore = stateToIsoMdocRequestStore,
                    decryptionKeyMaterial = decryptionKeyMaterial,
                    decryptHpke = ::testHpkeOpen,
                )

                /** Extracts the Annex C request from the browser-facing [CredentialRequestOptions]. */
                suspend fun createIsoMdocRequest(transactionId: String): IsoMdocRequest = verifier
                    .createAuthnRequest(
                        OpenId4VpRequestOptions(
                            presentationRequest = dcqlRequest,
                            responseMode = OpenIdConstants.ResponseMode.DcApi,
                            expectedOrigins = listOf(callingOrigin),
                            state = transactionId,
                        ),
                        DcApiCreationOptions.Iso180137AnnexC,
                    ).getOrThrow()
                    .digital.requests.shouldBeSingleton().first()
                    .shouldBeInstanceOf<DigitalCredentialGetRequest.IsoMdoc>()
                    .data

                suspend fun walletResponse(
                    isoMdocRequest: IsoMdocRequest,
                    origin: String = callingOrigin,
                ) = createWalletResponse(holderAgent, holderKeyMaterial, isoMdocRequest, origin, requestedCredential)
            }
        }
    }) - {

        test("createAuthnRequest renders device request and encryption info, and remembers the request") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val itemsRequest = isoMdocRequest.deviceRequest.docRequests.single().itemsRequest.value
            itemsRequest.docType shouldBe AtomicAttribute2023.isoDocType
            itemsRequest.namespaces[AtomicAttribute2023.isoNamespace]!!.entries shouldBe listOf(
                SingleItemsRequest(CLAIM_GIVEN_NAME, false),
                SingleItemsRequest(CLAIM_DATE_OF_BIRTH, false),
            )
            isoMdocRequest.encryptionInfo.type shouldBe TYPE_DCAPI
            isoMdocRequest.encryptionInfo.encryptionParameters.nonce.shouldNotBeNull()
            isoMdocRequest.encryptionInfo.encryptionParameters.recipientPublicKey shouldBe
                    f.decryptionKeyMaterial.publicKey.toCoseKey().getOrThrow()

            f.stateToIsoMdocRequestStore.get(transactionId) shouldBe isoMdocRequest
        }

        test("Annex C walk-through: wallet response validates and contains requested claims") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            val result = f.verifier.validateResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).getOrThrow()

            result.documents.shouldBeSingleton().first().apply {
                validItems.firstOrNull { it.elementIdentifier == CLAIM_GIVEN_NAME }
                    .shouldNotBeNull().elementValue shouldBe "Susanne"
                validItems.firstOrNull { it.elementIdentifier == CLAIM_DATE_OF_BIRTH }
                    .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
                invalidItems shouldBe emptyList()
            }
        }

        test("origin mismatch: session transcript differs, device signature verification fails") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            f.verifier.validateResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = "https://evil.example.com",
            ).isFailure shouldBe true
        }

        test("wallet responding to a different encryption info fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)
            // wallet answers a request with the same decryption key, but a different nonce,
            // i.e. its session transcript is not the one the verifier will calculate
            val otherRequest = isoMdocRequest.copy(
                encryptionInfo = isoMdocRequest.encryptionInfo.copy(
                    encryptionParameters = isoMdocRequest.encryptionInfo.encryptionParameters.copy(
                        nonce = ByteArray(16) { it.toByte() }
                    )
                )
            )

            val dcApiResponse = f.walletResponse(otherRequest)

            f.verifier.validateResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }

        test("unknown transaction id fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            f.verifier.validateResponse(
                receivedData = dcApiResponse,
                externalId = "unknown-${uuid4()}",
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }

        test("tampered ciphertext fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)
            val tampered = dcApiResponse.response.encryptedResponseData.cipherText
                .also { it[0] = (it[0].toInt() xor 0x01).toByte() }
                .let { DCAPIResponse(EncryptedResponse(TYPE_DCAPI, EncryptedResponseData(dcApiResponse.response.encryptedResponseData.enc, it))) }

            f.verifier.validateResponse(
                receivedData = tampered,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }
    }
}

/**
 * Simulates the wallet: computes the Annex C session transcript from the received [isoMdocRequest]
 * and its own [origin], creates a device response with the device signature over that transcript,
 * and encrypts it to the verifier's public key from the encryption info.
 */
private suspend fun createWalletResponse(
    holder: Holder,
    holderKeyMaterial: KeyMaterial,
    isoMdocRequest: IsoMdocRequest,
    origin: String,
    requestedCredential: RequestOptionsCredential,
): DCAPIResponse {
    val sessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray(
                DCAPIInfo(isoMdocRequest.encryptionInfo, origin.serializeOrigin()!!)
            ).sha256(),
        )
    )
    val signer = SignCoseDetached<ByteArray>(keyMaterial = holderKeyMaterial)
    val deviceResponse = holder.createDefaultPresentation(
        request = PresentationRequestParameters(
            nonce = uuid4().toString(), // not relevant for mdoc device authentication
            audience = origin,
            calcIsoDeviceSignaturePlain = { input ->
                signer(
                    protectedHeader = null,
                    unprotectedHeader = null,
                    payload = coseCompliantSerializer.encodeToByteArray(
                        ByteStringWrapper(
                            DeviceAuthentication(
                                type = DeviceAuthentication.TYPE,
                                sessionTranscript = sessionTranscript,
                                docType = input.docType,
                                namespaces = input.deviceNameSpaceBytes,
                            )
                        )
                    ).wrapInCborTag(24),
                    serializer = ByteArraySerializer(),
                ).getOrThrow()
            }
        ),
        credentialPresentationRequest = CredentialPresentationRequestBuilder(requestedCredential).toDCQLRequest()!!,
    ).getOrThrow()
        .shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
        .verifiablePresentations.values.shouldBeSingleton().first().shouldBeSingleton().first()
        .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
        .deviceResponse

    val encryptedResponseData = testHpkeSeal(
        recipientPublicKey = isoMdocRequest.encryptionInfo.encryptionParameters.recipientPublicKey,
        plaintext = coseCompliantSerializer.encodeToByteArray(deviceResponse),
        info = coseCompliantSerializer.encodeToByteArray(sessionTranscript),
    )
    return DCAPIResponse(EncryptedResponse(TYPE_DCAPI, encryptedResponseData))
}

// ponytail: stand-in for HPKE (RFC 9180), which is not available in signum supreme 0.14:
// ephemeral ECDH + SHA-256 KDF over (sharedSecret || info) + AES-256-GCM.
// [DcApiVerifier.validateResponse] takes the HPKE decryption function as a parameter,
// so actual HPKE interop is out of scope here; this pair still binds the response to the
// verifier's decryption key and the session transcript. Replace with signum HPKE once available.
private suspend fun testHpkeSeal(
    recipientPublicKey: CoseKey,
    plaintext: ByteArray,
    info: ByteArray,
): EncryptedResponseData {
    val recipientKey = recipientPublicKey.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
    val ephemeralKey = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1).getOrThrow()
    val sharedSecret = ephemeralKey.keyAgreement(recipientKey).getOrThrow()
    val sealedBox = testHpkeKey(sharedSecret, info).encrypt(plaintext).getOrThrow()
    return EncryptedResponseData(
        enc = ephemeralKey.publicValue.asCryptoPublicKey().iosEncoded,
        cipherText = sealedBox.nonce + sealedBox.encryptedData + sealedBox.authTag,
    )
}

private suspend fun testHpkeOpen(
    enc: ByteArray,
    cipherText: ByteArray,
    recipientPrivateKey: CryptoPrivateKey.EC.WithPublicKey,
    info: ByteArray,
): ByteArray {
    val ephemeralPublicKey = CryptoPublicKey.fromIosEncoded(enc) as CryptoPublicKey.EC
    val sharedSecret = (recipientPrivateKey as KeyAgreementPrivateValue).keyAgreement(ephemeralPublicKey).getOrThrow()
    return testHpkeKey(sharedSecret, info).decrypt(
        nonce = cipherText.copyOfRange(0, NONCE_LENGTH),
        encryptedData = cipherText.copyOfRange(NONCE_LENGTH, cipherText.size - AUTH_TAG_LENGTH),
        authTag = cipherText.copyOfRange(cipherText.size - AUTH_TAG_LENGTH, cipherText.size),
    ).getOrThrow()
}

private fun testHpkeKey(sharedSecret: ByteArray, info: ByteArray) =
    SymmetricEncryptionAlgorithm.AES_256.GCM.keyFrom((sharedSecret + info).sha256()).getOrThrow()

private const val NONCE_LENGTH = 12
private const val AUTH_TAG_LENGTH = 16
