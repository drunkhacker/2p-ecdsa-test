import com.n1analytics.paillier.EncryptedNumber
import com.n1analytics.paillier.PaillierPrivateKey
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.DSAKCalculator
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.math.ec.ECConstants
import org.bouncycastle.math.ec.ECMultiplier
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

val CURVE = "secp256k1"
val plainMessage = "Hello, World! this is test for ecdsa"

fun main(args: Array<String>) {
//    signTest()
    val ecp = ECNamedCurveTable.getParameterSpec(CURVE)

    /*********************/
    /***** 2P ECDSA ******/
    /*********************/
    val (k1, k2, k) = generateRandomMultiple(ecp.n)
    val (d1, d2, d) = generateRandomMultiple(ecp.n)

    val alice = Party1(ecp, k1, d1, plainMessage)
    val bob = Party2(ecp, k2, d2, plainMessage)

    // distributed key gen
    val Q1 = alice.step1_calc_Q1()
    val Q2 = bob.step1_calc_Q2()

    val q1 = alice.step2_calc_Q(Q2)
    val q2 = bob.step2_calc_Q(Q1)
    assert(q1.equals(q2))
    val q = q1 // q is public key

    // signing
    val R1 = alice.step1_calc_R1()
    val R2 = bob.step1_calc_R2()

    val r1 = alice.step2_calc_r(R2)
    val r2 = bob.step2_calc_r(R1)
    assert(r1 == r2)

    val ckey = alice.step3_create_ckey()

    val almostSig = bob.step3_create_almost_sig(ckey)

    val (r_2party, s_2party) = alice.step4_calc_and_verify_sig(almostSig)

    println("[2party] r=$r_2party , s=$s_2party")

    // verify sig
    val verifier = ECDSASigner()
    val pubkey = ECPublicKeyParameters(q, ecp.toECDomainParameters())
    println("pubkey = ${pubkey.q.xCoord}")

    verifier.init(false, pubkey)
    val mba = messageDigest.digest(plainMessage.toByteArray())
    val verified = verifier.verifySignature(mba, r_2party, s_2party)
    assert(verified)
    println("[2party] verified = $verified")

    /*********************/
    /*** classic ECDSA ***/
    /*********************/
    val signer = ECDSASigner(StaticK(k)) // fixed 'k' for demonstration purpose
    signer.init(true, ECPrivateKeyParameters(d, ecp.toECDomainParameters()))
    val (r_classic, s_classic) = signer.generateSignature(mba)

    println("[normal] r=$r_classic , s=$s_classic")

    assert(r_2party == r_classic)
    assert(s_2party == s_classic)

    verifier.init(false, pubkey)
    val verified2 = verifier.verifySignature(mba, r_2party, s_2party)
    assert(verified2)
    println("[normal] verified = $verified2")

}

fun signTest() {
    val ecp = ECNamedCurveTable.getParameterSpec(CURVE)
    var n: BigInteger
    var prvKey1: PaillierPrivateKey

    val bitLen = ecp.n.bitLength()*2

    do {
        prvKey1 = PaillierPrivateKey.create(bitLen)
        n = prvKey1.publicKey.modulus
    } while (n < ecp.n)

    val (k1, k2, k) = generateRandomMultiple(ecp.n)
    assert((k1*k2).mod(ecp.n).equals(k))
    val (d1, d2, d) = generateRandomMultiple(ecp.n)
    assert((d1*d2).mod(ecp.n).equals(d))

    val (r1, s1) = normalSign(ecp, k, d, plainMessage)

    // test 2party
    val (r2, s2) = sign2Party(ecp, prvKey1, k1, k2, d1, d2, plainMessage)

    // verify sign
    val verifier = ECDSASigner()
    val pubkey = getPublicKey(ECPrivateKeySpec(d, ecp))
    println("pubkey = ${pubkey.q.xCoord}")

    verifier.init(false, pubkey)
    val md = MessageDigest.getInstance("SHA1")
    val mba = md.digest(plainMessage.toByteArray())
    val verified1 = verifier.verifySignature(mba, r1, s1)
    println("[normal] verified = $verified1")

    val verified2 = verifier.verifySignature(mba, r2, s2)
    println("[2party] verified = $verified2")

}

fun normalSign(ecp: ECNamedCurveParameterSpec, k: BigInteger, d: BigInteger, plainMessage: String): Pair<BigInteger, BigInteger> {
//    val pkeySpec = ECPrivateKeySpec(d, ecp)

//    Security.addProvider(BouncyCastleProvider())
//    val kf = KeyFactory.getInstance("EC")
//    val pkey = kf.generatePrivate(pkeySpec)
//    val ecdsa = Signature.getInstance("SHA1withECDSA")
//    ecdsa.initSign(pkey)

    val kCalculator = StaticK(k)

    val signer = ECDSASigner(kCalculator)
    signer.init(true, ECPrivateKeyParameters(d, ecp.toECDomainParameters()))

    val md = MessageDigest.getInstance("SHA1")
    val mba = md.digest(plainMessage.toByteArray())

    val (r1,s1) = generateSignature(ECPrivateKeyParameters(d, ecp.toECDomainParameters()), kCalculator, mba)
    println("[normal] manual r=$r1, s=$s1")

    val (r,s) = signer.generateSignature(mba)
    println("[normal] signer r=$r, s=$s")

    assert(r1 == r)
    assert(s1 == s)

//    val signer2 = ECDSASigner()
//    val pubkey = getPublicKey(ECPrivateKeySpec(d, ecp))
//    println("pubkey = ${pubkey.q.xCoord}")
//
//    signer2.init(false, pubkey)
//    val verified = signer2.verifySignature(mba, r, s)
//    assert(verified)

    return Pair(r,s)
}

fun sign2Party(ecp: ECNamedCurveParameterSpec, ppkey: PaillierPrivateKey, k1: BigInteger, k2: BigInteger, d1: BigInteger, d2: BigInteger, plainMessage: String): Pair<BigInteger, BigInteger> {
//    val prvKey1 = PaillierPrivateKey.create(ecp.n.bitLength())
    val pubKey1 = ppkey.publicKey
    val n = pubKey1.modulus

//    val prvKey2 = PaillierPrivateKey.create(ecp.n.bitLength())
//    val pubKey2 = prvKey2.publicKey

    // let's get kG = r
    val basePointMultiplier = FixedPointCombMultiplier()
    val k1G = basePointMultiplier.multiply(ecp.g, k1)
    val kG = basePointMultiplier.multiply(k1G, k2).normalize()
    val r = kG.affineXCoord.toBigInteger().mod(ecp.n)

    val k = k1*k2
    val p = basePointMultiplier.multiply(ecp.g, k).normalize()
    val r2 = p.affineXCoord.toBigInteger().mod(ecp.n)

    assert(r.equals(r2))

//    val kG2 = basePointMultiplier.multiply(ecp.g, ks.third).normalize()
//    val r2 = kG2.affineXCoord.toBigInteger().mod(ecp.n)
//
    println("[2party] k1=$k1, k2=$k2, k=$k")

    // common knowledge
    val md = MessageDigest.getInstance("SHA1")
    val mba = md.digest(plainMessage.toByteArray())
    val e = calculateE(ecp.n, mba) // actually this is Z

    // P1 turn
    val paillierContext1 = pubKey1.createUnsignedContext()
    val ckey = paillierContext1.encrypt(d1)
    val d1_dec = ckey.decrypt(ppkey).decodeBigInteger()
    assert(d1 == d1_dec)

    assert( ckey.multiply(d2).decrypt(ppkey).decodeBigInteger().equals(d1*d2))

    // now P2 turn
    val k2Inv = BigIntegers.modOddInverse(ecp.n, k2)
    val k2Inv_z = (k2Inv*e).mod(ecp.n)
    val k2Inv_z_enc = paillierContext1.encrypt(k2Inv_z)
    val k2Inv_z_dec = k2Inv_z_enc.decrypt(ppkey).decodeBigInteger()
    assert(k2Inv_z_dec == k2Inv_z)

    val k2Inv_r_d2 = (k2Inv*r*d2).mod(ecp.n)
    val k2Inv_r_d2_d1_enc = ckey.multiply(k2Inv_r_d2) // Enc(k2^-1 * r * d2 * d1)

    paillierContext1.encrypt(k2Inv_r_d2).multiply(d1).decrypt(ppkey).decodeBigInteger()


    val k2Inv_r_d2_d1_dec = k2Inv_r_d2_d1_enc.decrypt(ppkey).decodeBigInteger().mod(ecp.n)
//    println("k2Inv_r_d2_d1_dec=$k2Inv_r_d2_d1_dec, k2Inv_r_d2=$k2Inv_r_d2, k2Inv_r_d2_d1 = $k2Inv_r_d2_d1")
    assert(k2Inv_r_d2_d1_dec == k2Inv_r_d2.multiply(d1).mod(ecp.n))

    val almostSig = k2Inv_z_enc.add(k2Inv_r_d2_d1_enc)

//    val xx = almostSig.decrypt(ppkey).decodeBigInteger()
//    k2Inv_z +

    // now P1 turn
    val k1Inv = BigIntegers.modOddInverse(ecp.n, k1)
    val kInv = BigIntegers.modOddInverse(ecp.n, k1*k2)
    val s = (almostSig.decrypt(ppkey).decodeBigInteger().multiply(k1Inv)).mod(ecp.n)
    // for testing
//    val s2 = (k1Inv * (k2Inv_z + (k2Inv_r_d2*d1).mod(n))).mod(n)
//
//    val s3 = (k1Inv*k2Inv*(e + r*d2*d1)).mod(n)
//    val s4 = (kInv*(e + r*d2*d1)).mod(n)
//
//    val d = d1*d2
//    val s5 = BigIntegers.modOddInverse(n, k).multiply(e.add(d.multiply(r))).mod(n)
    println("[2party] n=$n, e=$e")

    println("[2party] r=$r, s=$s")
//    println("[2party] s2=$s2, s3=$s3, s4=$s4, s5=$s5")

    return Pair(r,s)
}

class StaticK(private val k: BigInteger): DSAKCalculator {
    override fun isDeterministic() = true

    override fun init(n: BigInteger?, random: SecureRandom?) {

    }

    override fun init(n: BigInteger?, d: BigInteger?, message: ByteArray?) {

    }

    override fun nextK(): BigInteger {
//        println("nextK = $k")
        return k
    }
}

class MyDSAKCalculator : DSAKCalculator {
    private lateinit var q: BigInteger

    override fun isDeterministic() = true
    override fun nextK(): BigInteger {
        return BigInteger("110788715217991986268698795236795615328148691200225131206292230285780644286443")

        var k: BigInteger
        do {
            k = generateRandomMultiple(q).third
        } while(k == BigInteger.valueOf(0) || k >= q)
        return k
    }

    override fun init(n: BigInteger, d: BigInteger?, message: ByteArray?) {
        q = n
        println("bitlength=${q.bitLength()}")
    }

    override fun init(n: BigInteger?, random: SecureRandom?) {
        TODO("Not yet implemented")
    }
}

fun generateRandomMultiple(modulus: BigInteger): Triple<BigInteger, BigInteger, BigInteger> {
//    val keyPair = PaillierPrivateKey.create(bitLength)
//    val p = keyPair.getP()
//    val q = keyPair.getQ()

    val secureRandom = CryptoServicesRegistrar.getSecureRandom()

    val bitLength = modulus.bitLength()
    var p: BigInteger
    var q: BigInteger
    var pq: BigInteger
    do {
        p = BigIntegers.createRandomBigInteger(bitLength / 2, secureRandom)
        q = BigIntegers.createRandomBigInteger(bitLength / 2, secureRandom)
        pq = p*q
    }  while(!(pq.bitLength() == bitLength && pq < modulus))
//    println("p: $p, q: $q, pq: $pq")

    return Triple(p, q, pq)
}

fun getPublicKey(pkey: ECPrivateKeySpec): ECPublicKeyParameters {
    val q = pkey.params.g.multiply(pkey.d)
    return ECPublicKeyParameters(q, pkey.params.toECDomainParameters())
}

fun ECParameterSpec.toECDomainParameters() = ECDomainParameters(this.curve, this.g, this.n, this.h)
fun ECNamedCurveParameterSpec.toECDomainParameters() = ECDomainParameters(curve, g, n, h)


// from org.bouncycastle.crypto.signers.ECDSASigner

// 5.3 pg 28
fun generateSignature(
    key: ECKeyParameters,
    kCalculator: DSAKCalculator,
    message: ByteArray
): Array<BigInteger> {
    val ec: ECDomainParameters = key.getParameters()
    val n = ec.n
    val e: BigInteger = calculateE(n, message)
    val d = (key as ECPrivateKeyParameters).d
    if (kCalculator.isDeterministic()) {
        kCalculator.init(n, d, message)
    } else {
        throw Exception("not here")
    }
    var r: BigInteger
    var s: BigInteger
    val basePointMultiplier: ECMultiplier = FixedPointCombMultiplier()

    // 5.3.2
    do  // generate s
    {
        var k: BigInteger
        do  // generate r
        {
            k = kCalculator.nextK()
            val p = basePointMultiplier.multiply(ec.g, k).normalize()

            // 5.3.3
            r = p.affineXCoord.toBigInteger().mod(n)
        } while (r == ECConstants.ZERO)
        s = BigIntegers.modOddInverse(n, k).multiply(e.add(d.multiply(r))).mod(n)
    } while (s == ECConstants.ZERO)
//    println("generateSignature, r = $r")

    return arrayOf(r, s)
}

fun calculateE(n: BigInteger, message: ByteArray): BigInteger {
    val log2n = n.bitLength()
    val messageBitLength = message.size * 8
    var e = BigInteger(1, message)
    if (log2n < messageBitLength) {
        e = e.shiftRight(messageBitLength - log2n)
    }
    return e
}

val messageDigest = MessageDigest.getInstance("SHA1")

class Party1(
    private val ecp: ECNamedCurveParameterSpec,
    private val k1: BigInteger,
    private val d1: BigInteger,
    private val plainMessage: String,
) {
    private val mba = messageDigest.digest(plainMessage.toByteArray())
    private val e = calculateE(ecp.n, mba) // actually this is Z
    private val basePointMultiplier = FixedPointCombMultiplier()
    lateinit var r: BigInteger
    lateinit var q: ECPoint
    val publicKey: ECPublicKeyParameters by lazy {
        ECPublicKeyParameters(q, ecp.toECDomainParameters())
    }

    private val ppkey: PaillierPrivateKey = run {
        var prvKey1: PaillierPrivateKey

        // paillier의 modulus 사이즈를 ecp에 있는것보다 충분히 크게 잡아야 paillier 위에서 곱셈연산하다가 괜히 mod 연산 결과 때문에 고생하지 않음
        // 타원곡선의 order의 제곱수정도면 충분하다. 왜냐면 계산 과정에서 paillier 위에서의 곱셈연산이 1번 발생하기 때문.
        val bitLen = ecp.n.bitLength() * 2
        var n: BigInteger
        do {
            prvKey1 = PaillierPrivateKey.create(bitLen)
            n = prvKey1.publicKey.modulus
        } while (n < ecp.n)
        prvKey1
    }

    fun step1_calc_Q1(): ECPoint {
        return basePointMultiplier.multiply(ecp.g, d1)
    }

    fun step2_calc_Q(Q2: ECPoint): ECPoint {
        q = Q2.multiply(d1)
        return q
    }

    fun step1_calc_R1(): ECPoint {
        val k1G = basePointMultiplier.multiply(ecp.g, k1)
        return k1G
    }

    fun step2_calc_r(R2: ECPoint): BigInteger {
        val p = R2.multiply(k1).normalize() // R2 = k2G, p = k1(k2G) = kG
        r = p.affineXCoord.toBigInteger().mod(ecp.n)
        return r
    }

    fun step3_create_ckey(): EncryptedNumber {
        val ctx = ppkey.publicKey.createUnsignedContext()
        val ckey = ctx.encrypt(d1)
        return ckey
    }

    fun step4_calc_and_verify_sig(almostSig: EncryptedNumber): Pair<BigInteger, BigInteger> {
        // almostSig = Enc(k2^-1 * (z + r*d))
        val k1Inv = BigIntegers.modOddInverse(ecp.n, k1)

        // k1^-1*(k2^-1 * (z + r*d)) = (k1^-1 * k2^-1) * (z + r*d) = k^-1 * (z + r*d) = s
        val s = (almostSig.decrypt(ppkey).decodeBigInteger().multiply(k1Inv)).mod(ecp.n)

        // verify
        val verifier = ECDSASigner()
        verifier.init(false, publicKey)
        val verified = verifier.verifySignature(mba, r, s)
        assert(verified)

        return Pair(r,s)
    }
}

class Party2(
    private val ecp: ECNamedCurveParameterSpec,
    private val k2: BigInteger,
    private val d2: BigInteger,
    private val plainMessage: String,
) {
    private val mba = messageDigest.digest(plainMessage.toByteArray())
    private val e = calculateE(ecp.n, mba) // actually this is Z
    private val basePointMultiplier = FixedPointCombMultiplier()
    lateinit var r: BigInteger
    lateinit var q: ECPoint

    fun step1_calc_Q2(): ECPoint {
        return basePointMultiplier.multiply(ecp.g, d2)
    }

    fun step2_calc_Q(Q1: ECPoint): ECPoint {
        q = Q1.multiply(d2)
        return q
    }

    fun step1_calc_R2(): ECPoint {
        val k2G = basePointMultiplier.multiply(ecp.g, k2)
        return k2G
    }

    fun step2_calc_r(R1: ECPoint): BigInteger {
        val p = R1.multiply(k2).normalize() // R1 = k1G, p = k2(k1G) = kG
        r = p.affineXCoord.toBigInteger().mod(ecp.n)
        return r
    }

    fun step3_create_almost_sig(ckey: EncryptedNumber): EncryptedNumber {
        val k2Inv = BigIntegers.modOddInverse(ecp.n, k2)
        val k2Inv_z = (k2Inv*e).mod(ecp.n)
        val k2Inv_z_enc = ckey.context.encrypt(k2Inv_z) // Enc(k2^-1 * z)

        val k2Inv_r_d2 = (k2Inv*r*d2).mod(ecp.n)
        val k2Inv_r_d2_d1_enc = ckey.multiply(k2Inv_r_d2) // Enc(d1) * (k2^-1 * r * d2) = Enc(d1 * k2^-1 * r * d2) = Enc(k2^-1 * r * d)

        val almostSig = k2Inv_z_enc.add(k2Inv_r_d2_d1_enc)
        //   Enc(k2^-1 * z) + Enc(d1 * k2^-1 * r * d2)
        // = Enc(k2^-1 * z + d1 * k2^-1 * r * d2)
        // = Enc(k2^-1 * z + k2^-1 * r * d)
        // = Enc(k2^-1 * (z + r*d))

        return almostSig
    }
}
