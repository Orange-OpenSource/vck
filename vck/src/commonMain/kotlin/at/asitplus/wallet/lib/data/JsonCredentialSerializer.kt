package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.JsonValueEncoder
import kotlinx.serialization.json.JsonElement
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

@OptIn(ExperimentalAtomicApi::class)
internal object JsonCredentialSerializer {

    private val jsonElementEncoderRef = AtomicReference(setOf<JsonValueEncoder>())

    fun register(function: JsonValueEncoder) {
        jsonElementEncoderRef.update { it + function }
    }

    fun encode(value: Any): JsonElement? =
        jsonElementEncoderRef.load().firstNotNullOfOrNull { it.invoke(value) }

}
