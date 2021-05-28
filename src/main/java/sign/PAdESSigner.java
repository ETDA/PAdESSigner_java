package sign;

import java.io.File;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.OCSPVerifier;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import pkcs.*;
import timestamp.TSAAuthenticationType;
import timestamp.TSAController;
import timestamp.TimeStamp;
import timestamp.TimeStampType;
import utility.FileSpecification;

public class PAdESSigner {
	
	/**
	 * Blank constructor
	 */
	public PAdESSigner() {

	}
	/**
	 * Sign a single file
	 * @param inputFilePath
	 * @param outputFilePath
	 * @param pkcsInstance
	 * @param digestAlgorithm
	 * @param signatureAppearance
	 * @param timeStamping
	 * @throws GeneralSecurityException
	 * @throws Exception
	 */
	public void signOnce(String inputFilePath, String outputFilePath, IPKCSInstance pkcsInstance, 
			DigestAlgorithm digestAlgorithm, SignatureAppearance signatureAppearance, TimeStamp timeStamping) throws GeneralSecurityException, Exception {

		// Get TimeStamp
		ITSAClient tsaClient = getTimeStampConnection(timeStamping);
		
		// Get the certificate chain, private key and key store provider into the CertificateKeyPack instance
		CertificateKeyPack certificateKeyPack = loadKeyStore(pkcsInstance);
        PrivateKey privateKey = certificateKeyPack.getPrivateKey();
        Certificate[] certificateChain = certificateKeyPack.getCertificateChain();
        String provider = certificateKeyPack.getProvider();
        
        List<String> crlURLList = new ArrayList<String>();
        
        
        for (int i = 0; i < certificateChain.length; i++) {
            X509Certificate cert = (X509Certificate) certificateChain[i];
            System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
            System.out.println("CRL: " + CertificateUtil.getCRLURL(cert));
            System.out.println("OCSP: " + CertificateUtil.getOCSPURL(cert));
            crlURLList.add(CertificateUtil.getCRLURL(cert));
        }
        
        
        // Get OCSP and CRL for long-term validation
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
		OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(ocspVerifier);
		List<ICrlClient> crlList = new ArrayList<ICrlClient>();
		//crlList.add(new CrlClientOnline());
		for (String crlURL : crlURLList) {
			crlList.add(new CrlClientOnline(crlURL));
			
		}
        
        //Call SignController class for signing
		SignController signController = new SignController();
        signController.sign(inputFilePath, outputFilePath, certificateChain, privateKey,
        		digestAlgorithm, provider, PdfSigner.CryptoStandard.CMS,
                signatureAppearance, crlList, ocspClient, tsaClient, 0);
        
        //signController.addLTV(outputFilePath, outputFilePath);
	}
	
	/**
	 * Sign multiple file
	 * @param inputFolderPath
	 * @param outputFolderPath
	 * @param outputSuffix
	 * @param pkcsInstance
	 * @param digestAlgorithm
	 * @param signatureAppearance
	 * @param timeStamping
	 * @throws GeneralSecurityException
	 * @throws Exception
	 */
	public void signMultiple(String inputFolderPath, String outputFolderPath, String outputSuffix, IPKCSInstance pkcsInstance, 
			DigestAlgorithm digestAlgorithm, SignatureAppearance signatureAppearance, TimeStamp timeStamping) throws GeneralSecurityException, Exception {
		
		// Get TimeStamp
		ITSAClient tsaClient = getTimeStampConnection(timeStamping);
		
		// Get the certificate chain, private key and key store provider into the CertificateKeyPack instance
		CertificateKeyPack certificateKeyPack = loadKeyStore(pkcsInstance);
        PrivateKey privateKey = certificateKeyPack.getPrivateKey();
        Certificate[] certificateChain = certificateKeyPack.getCertificateChain();
        String provider = certificateKeyPack.getProvider();
        
		List<String> crlURLList = new ArrayList<String>();  
        for (int i = 0; i < certificateChain.length; i++) {
            X509Certificate cert = (X509Certificate) certificateChain[i];
            System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
            System.out.println("CRL: " + CertificateUtil.getCRLURL(cert));
            System.out.println("OCSP: " + CertificateUtil.getOCSPURL(cert));
            crlURLList.add(CertificateUtil.getCRLURL(cert));
        }
		
        // Get OCSP and CRL for long-term validation
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
		OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(ocspVerifier);
        List<ICrlClient> crlList = new ArrayList<ICrlClient>();
		//crlList.add(new CrlClientOnline());
		for (String crlURL : crlURLList) {
			crlList.add(new CrlClientOnline(crlURL));
			
		}
        
		java.util.List<FileSpecification> fileSpecList = getFileFromFolder(inputFolderPath);
		
		for(FileSpecification fileSpec : fileSpecList) {
			
			System.out.println("Signing: " + fileSpec.getFileNameWithExtension());
			
			String inputFilePath = fileSpec.getFullFilePath();
			String outputFilePath = null;
			if (outputSuffix != null) {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + outputSuffix + "." + fileSpec.getFileExtension();
			} else {
				outputFilePath = outputFolderPath + "/" + fileSpec.getFileNameWithoutExtension() + "." + fileSpec.getFileExtension();
			}
			
			//Call SignController class for signing
			SignController signController = new SignController();
	        signController.sign(inputFilePath, outputFilePath, certificateChain, privateKey,
	        		digestAlgorithm, provider, PdfSigner.CryptoStandard.CMS,
	                signatureAppearance, crlList, ocspClient, tsaClient, 0);
		}
	}
	
	/**
	 * Get all file in specific folder
	 * @param folderPath
	 * @return List<FileSpecification>
	 */
	private java.util.List<FileSpecification> getFileFromFolder(String folderPath) {
		
		java.util.List<FileSpecification> fileSpecList = new java.util.ArrayList<FileSpecification>();
		
		File dir = new File(folderPath);
		File[] directoryListing = dir.listFiles();
		if (directoryListing != null) {
			for (File file : directoryListing) {
				FileSpecification fileSpecification = new FileSpecification();
				fileSpecification.setFullFilePath(file.getAbsolutePath());
				fileSpecification.setFileNameWithExtension(file.getName());
				fileSpecification.setFileNameWithoutExtension(file.getName().split("\\.")[0]);
				fileSpecification.setFileExtension(file.getName().split("\\.")[1]);
				fileSpecList.add(fileSpecification);
			}
		}
		return fileSpecList;
	}

	/**
	 * Get TSA instance
	 * @param timeStamping
	 * @return ITSAClient
	 */
	private ITSAClient getTimeStampConnection(TimeStamp timeStamping) {
		ITSAClient tsaClient = null;
		if (timeStamping == null) {
			tsaClient = null;
		} else if (timeStamping.getTimeStampingType() == TimeStampType.COMPUTER_CLOCK) {
			tsaClient = null;
		} else if (timeStamping.getTimeStampingType() == TimeStampType.TSA) {
			if (timeStamping.getTSAAuthenticationType() == TSAAuthenticationType.NO_AUTHENTICATION) {
				tsaClient = new TSAClientBouncyCastle(timeStamping.getURL(), "", "");
			} else if (timeStamping.getTSAAuthenticationType() == TSAAuthenticationType.USERNAME_PASSWORD) {
				tsaClient = new TSAClientBouncyCastle(timeStamping.getURL(), timeStamping.getUsername(), timeStamping.getPassword());
			} else if (timeStamping.getTSAAuthenticationType() == TSAAuthenticationType.CERTIFICATE) {
				tsaClient = new TSAController(timeStamping.getURL(), timeStamping.getUsername(), timeStamping.getPassword().toCharArray());
			}
		} 
		return tsaClient;
	}
	
	/**
	 * Get Certificate chain, private key and KeyStore provider from input KeyStore
	 * @param pkcsInstance
	 * @return CertificateKeyPack
	 * @throws Exception
	 */
	private CertificateKeyPack loadKeyStore(IPKCSInstance pkcsInstance) throws Exception {
		if (pkcsInstance instanceof PKCS12Instance) {
			
			CertificateKeyPack certificateKeyPack = new CertificateKeyPack();
			
			char[] passwordCharArr = ((PKCS12Instance)pkcsInstance).getKeyStorePassword().toCharArray();
	        BouncyCastleProvider provider = new BouncyCastleProvider();
	        Security.addProvider(provider);

	        // The first argument defines that the keys and certificates are stored using PKCS#12
	        KeyStore keyStore = KeyStore.getInstance("pkcs12", provider.getName());
	        keyStore.load(new FileInputStream(((PKCS12Instance)pkcsInstance).getFilePath()), passwordCharArr);
	        
	        String alias = keyStore.aliases().nextElement();
	        
	        certificateKeyPack.setPrivateKey((PrivateKey) keyStore.getKey(alias, passwordCharArr));
	        certificateKeyPack.setCertificateChain(keyStore.getCertificateChain(alias));
	        certificateKeyPack.setProvider(provider.getName());
	        
	        return certificateKeyPack;
	        
		} else if (pkcsInstance instanceof PKCS11Instance) {
			CertificateKeyPack certificateKeyPack = new CertificateKeyPack();
			boolean isKeyStoreFound = false;
			
			String pkcs11Config = String.format("name=%s\nlibrary=%s", ((PKCS11Instance)pkcsInstance).getTokenName(), ((PKCS11Instance)pkcsInstance).getLibraryPath());

			java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
			sun.security.pkcs11.SunPKCS11 provider = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
			java.security.Security.addProvider(provider);

			String pin = ((PKCS11Instance)pkcsInstance).getPin();
			KeyStore keyStore=KeyStore.getInstance("PKCS11",provider);
			keyStore.load(null, pin.toCharArray());
			
			java.util.Enumeration<String> aliases = keyStore.aliases();
			String alias = null;
			char[] passwordCharArr = ((PKCS11Instance) pkcsInstance).getKeyStorePassword().toCharArray();	
			
			System.out.println("\tCertificate subject found in X509Principle:");
			
			while (aliases.hasMoreElements()) {
			    alias = aliases.nextElement();
			    
			    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
			    System.out.println("\t\t" + certificate.getSubjectDN().getName());
			    
		        if (certificate.getSubjectDN().getName().contains(((PKCS11Instance)pkcsInstance).getSearchPhase())) {
		        	certificateKeyPack.setPrivateKey((PrivateKey) keyStore.getKey(alias, passwordCharArr));
		        	certificateKeyPack.setCertificateChain(keyStore.getCertificateChain(alias));	
		        	certificateKeyPack.setProvider(provider.getName());
		        	isKeyStoreFound = true;
		        	break;
		        }
		    }
			
			if (isKeyStoreFound == true) {
	        	return certificateKeyPack;
	        } else {
	        	throw new Exception("KeyStore was not found.");
	        }
		} else {
			throw new Exception("Unrecognized PKCSInstance class");
		}
	}
	
	// Nested class for store certificate chain and private key element
	private class CertificateKeyPack {
		private PrivateKey privateKey;
		private Certificate[] certificateChain;
		private String provider;
		
		/**
		 * Blank constructor
		 */
		protected CertificateKeyPack() {
			
		}
		
		/**
		 * Set the certificate chain
		 * @param certificateChain
		 */
		protected void setCertificateChain(Certificate[] certificateChain) {
			this.certificateChain = certificateChain;
		}
		
		/**
		 * Get the certificate chain
		 * @return Certificate[]
		 */
		protected Certificate[] getCertificateChain() {
			return certificateChain;
		}
		
		/**
		 * Set the private key
		 * @param privateKey
		 */
		protected void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}
		
		/**
		 * Get the private key
		 * @return PrivateKey 
		 */
		protected PrivateKey getPrivateKey() {
			return  privateKey;
		}

		/**
		 * Get the Provider
		 * @return String
		 */
		protected String getProvider() {
			return provider;
		}

		/**
		 * Set the provider
		 * @param Set the provider
		 */
		protected void setProvider(String provider) {
			this.provider = provider;
		}
	}
}
