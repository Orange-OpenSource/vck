package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

@OptIn(ExperimentalAtomicApi::class)
object CborCredentialSerializer {

    private data class NamespaceSerializers(
        val decoders: Map<String, ItemValueDecoder>,
        val encoders: Map<String, ItemValueEncoder>,
        val serializers: Map<String, KSerializer<*>>,
    )

    private val serializersByNamespaceRef = AtomicReference(emptyMap<String, NamespaceSerializers>())

    fun register(serializerMap: Map<String, KSerializer<*>>, isoNamespace: String) {
        val namespaceSerializers = NamespaceSerializers(
            decoders = serializerMap.mapValues { (_, serializer) -> decodeFun(serializer) },
            encoders = serializerMap.mapValues { (_, serializer) ->
                @Suppress("UNCHECKED_CAST")
                encodeFun(serializer as KSerializer<Any>)
            },
            serializers = serializerMap,
        )
        serializersByNamespaceRef.update { it + (isoNamespace to namespaceSerializers) }
    }

    private fun decodeFun(ser: KSerializer<*>) =
        { descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder ->
            compositeDecoder.decodeSerializableElement(descriptor, index, ser)!!
        }

    private fun encodeFun(ser: KSerializer<Any>) =
        { descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any ->
            compositeEncoder.encodeSerializableElement(descriptor, index, ser, value)
        }

    fun lookupSerializer(namespace: String, elementIdentifier: String): KSerializer<*>? =
        serializersByNamespaceRef.load()[namespace]?.serializers?.get(elementIdentifier)

    fun encode(
        namespace: String,
        elementIdentifier: String,
        descriptor: SerialDescriptor,
        index: Int,
        compositeEncoder: CompositeEncoder,
        value: Any,
    ) {
        serializersByNamespaceRef.load()[namespace]?.encoders?.get(elementIdentifier)
            ?.invoke(descriptor, index, compositeEncoder, value)
    }

    fun decode(
        descriptor: SerialDescriptor,
        index: Int,
        compositeDecoder: CompositeDecoder,
        elementIdentifier: String,
        isoNamespace: String,
    ): Any? = serializersByNamespaceRef.load()[isoNamespace]?.decoders?.get(elementIdentifier)?.let {
        catchingUnwrapped { it.invoke(descriptor, index, compositeDecoder) }.getOrNull()
    }
}

fun ByteArray.stripCborTag(tag: Byte): ByteArray {
    val tagBytes = byteArrayOf(0xd8.toByte(), tag)
    return if (this.take(tagBytes.size).toByteArray().contentEquals(tagBytes)) {
        this.drop(tagBytes.size).toByteArray()
    } else {
        this
    }
}

fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

fun ByteArray.sha256(): ByteArray = Digest.SHA256.digest(this)


private typealias ItemValueEncoder
        = (descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) -> Unit

private typealias ItemValueDecoder
        = (descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder) -> Any
