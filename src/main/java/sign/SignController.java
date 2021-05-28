package sign;

 import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.layout.element.Image;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.SignatureUtil;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.LtvVerification;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfPKCS7;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.x509.util.StreamParsingException;

import org.apache.commons.io.FileUtils;


public class SignController {
	
	/***
	 * Sign PDF document using signDetached
	 * 
	 * @param src The source (input) file
	 * @param dest The destination (output) file
	 * @param chain The Certificate chain
	 * @param pk The private key
	 * @param digestAlgorithm The hash digest algorithm
	 * @param provider The KeyStore provider
	 * @param subfilter The CryptoStandard
	 * @param signatureAppearance The appearance of signature
	 * @param crlList The certificate revocation list
	 * @param ocspClient The Online Certificate Status Protocol
	 * @param tsaClient The TimeStamp authority instance and connection detail
	 * @param estimatedSize The reserved size for the signature
	 * @throws Exception
	 */
	public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
			DigestAlgorithm digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            SignatureAppearance signatureAppearance, Collection<ICrlClient> crlList,
            IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
            throws Exception {
        PdfReader reader = new PdfReader(src);
        //PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), signatureAppearance.getLocation(), false); => Comment out due to iText 7 Deprecation
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        Rectangle rect = new Rectangle(signatureAppearance.getX(), signatureAppearance.getY(), signatureAppearance.getWidth(), signatureAppearance.getHeight());
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason(signatureAppearance.getReason())
                .setLocation(signatureAppearance.getLocation())
                .setReuseAppearance(false)
                .setPageRect(rect)
                .setPageNumber(signatureAppearance.getPageNumber());
        
        ImageData image = null;
        if (signatureAppearance.getSignatureImage() != null) {
        	image = ImageDataFactory.create(signatureAppearance.getSignatureImage());
        	appearance.setSignatureGraphic(image);
        }
        
        if (signatureAppearance.getSignatureVisibility() == SignatureVisibility.VISIBLE) {
        	switch (signatureAppearance.getSignaturePattern()) {
        	case DESCRIPTION:
        		appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        		break;
        	case NAME_AND_DESCRIPTION:
        		appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
        		break;
        	case GRAPHIC_AND_DESCRIPTION:
        		appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
        		appearance.setSignatureGraphic(image);
        		break;
        	case GRAPHIC:       		
        		appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
        		appearance.setSignatureGraphic(image);
        		break;
        	default:
        		appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        		break;
        	}
        }
        
        signer.setFieldName(signatureAppearance.getSignatureFieldName());
        
        
        switch (signatureAppearance.getSignatureLevel()) {
        case APPROVAL:
        	signer.setCertificationLevel(0);
        	break;
        case CERTIFIED_NO_CHANGES_ALLOW:
        	signer.setCertificationLevel(1);
        	break;
        case CERTIFIED_FORM_FILLING:
        	signer.setCertificationLevel(2);
        	break;
        case CERTIFIED_FORM_FILLING_AND_ANNOTATIONS:
        	signer.setCertificationLevel(3);
        	break;
        default:
        	signer.setCertificationLevel(0);
        	break;
        }
       
        String digestAlgorithmString = null;
        switch (digestAlgorithm) {
        	case SHA256:
        		digestAlgorithmString = "SHA256";
        		break;
        	case SHA384:
        		digestAlgorithmString = "SHA384";
        		break;
        	case SHA512:
        		digestAlgorithmString = "SHA512";
        		break;
        	default:
        		throw new Exception("Unrecognized/Unsupported algorithm");
        }
        
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithmString, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
        
        reader.close();
    }
}
