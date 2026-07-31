package at.asitplus.wallet.lib.data.rfc1950

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc1950.primitives.Nibble
import io.kotest.matchers.shouldBe

val CompressionMethodAndFlagsTest by matrixSuite {
    "check properties" - {
        data((0..Nibble.MAX_VALUE).map {
                it.toByte()
            }) test {
            CompressionMethodAndFlags(it).compressionMethod.value shouldBe it

            val value = it.toInt().shl(4).toUByte().toByte()
            CompressionMethodAndFlags(value).compressionInfo.value shouldBe it
        }
    }
}