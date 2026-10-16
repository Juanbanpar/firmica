import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;

import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.cades.CAdESValidator;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.cms.Attribute;
import org.spongycastle.asn1.ess.SigningCertificateV2;
import org.spongycastle.cms.CMSProcessableByteArray;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;

// Runs only against disposable synthetic keys and documents. This reference code
// and its pinned AutoFirma/SpongyCastle dependencies are never part of the client.
class CadesReference {
    public static void main(String[] args) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(args[0]))) {
            store.load(input, "synthetic-test".toCharArray());
        }
        var entry = (KeyStore.PrivateKeyEntry) store.getEntry(
            store.aliases().nextElement(),
            new KeyStore.PasswordProtection("synthetic-test".toCharArray()));
        var certificate = (X509Certificate) entry.getCertificate();
        byte[] document = Files.readAllBytes(Path.of(args[1]));
        byte[] ours = Files.readAllBytes(Path.of(args[2]));
        boolean attached = args[3].equals("attached");
        require(CAdESValidator.isCAdESSignedData(ours, true), "AutoFirma CAdES recognition");
        SignerInformation ourSigner = verify(ours, document, attached, certificate);

        Properties options = new Properties();
        options.setProperty("profile", "baseline");
        options.setProperty("mode", attached ? "implicit" : "explicit");
        byte[] reference = new AOCAdESSigner().sign(document, args[4],
            entry.getPrivateKey(), entry.getCertificateChain(), options);
        Files.write(Path.of(args[5]), reference);
        SignerInformation referenceSigner = verify(reference, document, attached, certificate);
        require(ourSigner.getDigestAlgOID().equals(referenceSigner.getDigestAlgOID()), "digest algorithm");
        require(ourSigner.getEncryptionAlgOID().equals(referenceSigner.getEncryptionAlgOID()), "signature algorithm");
        require(ourSigner.getSID().equals(referenceSigner.getSID()), "signer identity");
        for (String id : new String[] { "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4" }) {
            require(value(ourSigner, id).getAttrValues().equals(value(referenceSigner, id).getAttrValues()), "attribute " + id);
        }
        // AutoFirma adds optional issuerSerial and content hints. Time and ECDSA
        // randomness also differ; compare the shared semantics rather than bytes.
        require(Arrays.equals(binding(ourSigner), binding(referenceSigner)), "certificate binding");
    }

    private static SignerInformation verify(byte[] encoded, byte[] document,
            boolean attached, X509Certificate certificate) throws Exception {
        CMSSignedData data = attached ? new CMSSignedData(encoded)
            : new CMSSignedData(new CMSProcessableByteArray(document), encoded);
        require(data.isDetachedSignature() != attached, "content mode");
        require(data.getSignerInfos().size() == 1, "one signer");
        var signer = data.getSignerInfos().getSigners().iterator().next();
        require(signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
            .setProvider(new BouncyCastleProvider()).build(certificate)), "SpongyCastle signature verification");
        require(Arrays.equals((byte[]) data.getSignedContent().getContent(), document), "exact content");
        require(Arrays.equals(binding(signer), MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())), "full DER certificate hash");
        value(signer, "1.2.840.113549.1.9.5");
        return signer;
    }

    private static Attribute value(SignerInformation signer, String id) {
        var oid = new ASN1ObjectIdentifier(id);
        require(signer.getSignedAttributes().getAll(oid).size() == 1, "one attribute " + id);
        Attribute attribute = signer.getSignedAttributes().get(oid);
        require(attribute.getAttrValues().size() == 1, "one value " + id);
        return attribute;
    }

    private static byte[] binding(SignerInformation signer) {
        var binding = SigningCertificateV2.getInstance(
            value(signer, "1.2.840.113549.1.9.16.2.47").getAttrValues().getObjectAt(0));
        require(binding.getCerts().length == 1, "one signing certificate reference");
        require(binding.getCerts()[0].getHashAlgorithm().getAlgorithm().getId()
            .equals("2.16.840.1.101.3.4.2.1"), "SHA-256 certificate reference");
        require(binding.getPolicies() == null, "no certification policies in ESS");
        return binding.getCerts()[0].getCertHash();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
