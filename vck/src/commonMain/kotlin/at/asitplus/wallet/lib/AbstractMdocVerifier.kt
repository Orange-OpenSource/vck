package at.asitplus.wallet.lib

import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun

@Deprecated("Logic moved to MdocDeviceSignatureVerifier")
abstract class AbstractMdocVerifier {
    /** Creates challenges in authentication requests. */
    protected abstract val nonceService: NonceService

    /** Used for encrypted responses. */
    protected abstract val decryptionKeyMaterial: KeyMaterial

    /** Used to verify session transcripts from mDoc responses. */
    protected abstract val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray>

    // Get's removed in 8.0.0
    protected abstract fun createDcApiSessionTranscript(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript

    /**
     * Performs verification of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    protected fun verifyDocument(
        sessionTranscript: SessionTranscript
    ): suspend (MobileSecurityObject, Document) -> Boolean =
        MdocDeviceSignatureVerifier(verifyCoseSignature = verifyCoseSignature).verifyDocument(sessionTranscript)


}