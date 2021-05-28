package controller;

import java.time.Duration;
import java.time.Instant;
import java.util.Scanner;

import pkcs.PKCS11Instance;
import pkcs.PKCS12Instance;
import sign.DigestAlgorithm;
import sign.PAdESSigner;
import sign.SignatureAppearance;
import sign.SignatureLevel;
import sign.SignaturePattern;
import sign.SignatureVisibility;
import timestamp.TSAAuthenticationType;
import timestamp.TimeStamp;
import timestamp.TimeStampType;
import utility.ParameterController;

public class Runnable {

	public static void main(String[] args)  {
		try {
			Instant start = Instant.now();
			
			runWithExternalInput(args);
			Instant end = Instant.now();
			Duration timeElapsed = Duration.between(start, end); 
			System.out.println("Total process time " + timeElapsed.getSeconds());
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			System.out.println("Press enter to exit.");
			(new Scanner(System.in)).nextLine();
		}
		
	}

	public static void runWithExternalInput(String[] args) {
		try {
			
			ParameterController paramCtrl = new ParameterController(args);
			
			// Input-Output
			String signType = paramCtrl.getParameterValue("-signType");
		    String inputFile = paramCtrl.getParameterValue("-inputFile");
			String outputFile = paramCtrl.getParameterValue("-outputFile");
			String inputFolder = paramCtrl.getParameterValue("-inputFolder");
			String outputFolder = paramCtrl.getParameterValue("-outputFolder");
			String outputSuffix = paramCtrl.getParameterValue("-outputSuffix");
			
			//PKCS12 Parameter
			String pkcs12FilePath = paramCtrl.getParameterValue("-pkcs12FilePath");
			String pkcs12Password = paramCtrl.getParameterValue("-pkcs12Password");
			
			//PKCS11 Parameter
			String pkcs11TokenName = paramCtrl.getParameterValue("-pkcs11TokenName");
			String pkcs11LibraryPath = paramCtrl.getParameterValue("-pkcs11LibraryPath");
			String pkcs11TokenPin = paramCtrl.getParameterValue("-pkcs11Pin");
			String pkcs11KeyStorePassword = paramCtrl.getParameterValue("-pkcs11KeyStorePassword");
			String pkcs11SearchKeyword = paramCtrl.getParameterValue("-pkcs11SeachKeyword");
			
			//TimeStamp URL
			TimeStampType timeStampingType = paramCtrl.getParameterValue("-timeStampType") != null ? TimeStampType.valueOf(paramCtrl.getParameterValue("-timeStampType")) : null;
			TSAAuthenticationType tsaAuthenticationType = paramCtrl.getParameterValue("-tsaAuthenticationType") != null ? TSAAuthenticationType.valueOf(paramCtrl.getParameterValue("-tsaAuthenticationType")) : null;
			String tsaURL = paramCtrl.getParameterValue("-tsaURL");
			String tsaUsername = paramCtrl.getParameterValue("-tsaUsername");
			String tsaPassword = paramCtrl.getParameterValue("-tsaPassword");
			String tsaPKCS12File = paramCtrl.getParameterValue("-tsaPKCS12File");
			String tsaPKCS12Password = paramCtrl.getParameterValue("-tsaPKCS12Password");
			TimeStamp timeStamping;
			switch (timeStampingType) {
				case COMPUTER_CLOCK:
					timeStamping = new TimeStamp(timeStampingType);
					break;
				case TSA:
					switch (tsaAuthenticationType) {
					case NO_AUTHENTICATION:
						timeStamping = new TimeStamp(timeStampingType, tsaURL, tsaAuthenticationType);
						break;
					case USERNAME_PASSWORD:
						timeStamping = new TimeStamp(timeStampingType, tsaURL, tsaAuthenticationType, tsaUsername, tsaPassword);
						break;
					case CERTIFICATE:
						timeStamping = new TimeStamp(timeStampingType, tsaURL, tsaAuthenticationType, tsaPKCS12File, tsaPKCS12Password);
						break;
					default:
						throw new Exception("TSA authentication must be input");
					}
					break;
				default:
					timeStamping = new TimeStamp(TimeStampType.COMPUTER_CLOCK);
			}
			
			
			//Signature Appearance
			SignatureAppearance signatureAppearance = new SignatureAppearance();
			signatureAppearance.setLocation(paramCtrl.getParameterValue("-Location"));
			signatureAppearance.setReason(paramCtrl.getParameterValue("-Reason"));
			signatureAppearance.setX(Integer.parseInt(paramCtrl.getParameterValue("-X")));
			signatureAppearance.setY(Integer.parseInt(paramCtrl.getParameterValue("-Y")));
			signatureAppearance.setWidth(Integer.parseInt(paramCtrl.getParameterValue("-Width")));
			signatureAppearance.setHeight(Integer.parseInt(paramCtrl.getParameterValue("-Height")));
			signatureAppearance.setSignatureFieldName(paramCtrl.getParameterValue("-SignatureFieldName"));
			signatureAppearance.setPageNumber(Integer.parseInt(paramCtrl.getParameterValue("-PageNumber")));
			signatureAppearance.setSignatureLevel(paramCtrl.getParameterValue("-SignatureLevel") != null ? SignatureLevel.valueOf(paramCtrl.getParameterValue("-SignatureLevel")) : null);
			signatureAppearance.setSignatureVisibility(paramCtrl.getParameterValue("-SignatureVisibility") != null ? SignatureVisibility.valueOf(paramCtrl.getParameterValue("-SignatureVisibility")) : null);
			signatureAppearance.setSignaturePattern(paramCtrl.getParameterValue("-SignaturePattern") != null ? SignaturePattern.valueOf(paramCtrl.getParameterValue("-SignaturePattern")) : null);
			signatureAppearance.setSignatureImage(paramCtrl.getParameterValue("-SignatureImage"));
			
			//Other sign parameter
			DigestAlgorithm digestAlgorithm = paramCtrl.getParameterValue("-digestAlgorithm") != null ? DigestAlgorithm.valueOf(paramCtrl.getParameterValue("-digestAlgorithm")) : null;
			
			//PKCS
			PKCS12Instance pkcs12 = null;
			PKCS11Instance pkcs11 = null;
			
			if (pkcs12FilePath != null && pkcs12Password != null) {
				pkcs12 = new PKCS12Instance(pkcs12FilePath, pkcs12Password);
			} else if (pkcs11TokenName != null && pkcs11LibraryPath != null && pkcs11TokenPin != null && pkcs11KeyStorePassword != null && pkcs11SearchKeyword != null) {
				pkcs11 = new PKCS11Instance(pkcs11TokenName, pkcs11LibraryPath, pkcs11TokenPin, pkcs11KeyStorePassword, pkcs11SearchKeyword);
			} else {
				throw new Exception("Incomplete certificate input");
			}
			
			//Let's sign
			PAdESSigner padesSigner = new PAdESSigner();
			if (signType.equalsIgnoreCase("single")) {
				if (pkcs12 != null) {
					padesSigner.signOnce(inputFile, outputFile, pkcs12, digestAlgorithm, signatureAppearance, timeStamping);
				} else if ((pkcs11 != null)) {
					padesSigner.signOnce(inputFile, outputFile, pkcs11, digestAlgorithm, signatureAppearance, timeStamping);
				}
			}
			else if (signType.equalsIgnoreCase("multiple")) {
				if (pkcs12 != null) {
						padesSigner.signMultiple(inputFolder, outputFolder, outputSuffix, pkcs12, digestAlgorithm, signatureAppearance, timeStamping);
					} else if ((pkcs11 != null)) {
						padesSigner.signMultiple(inputFolder, outputFolder, outputSuffix, pkcs11, digestAlgorithm, signatureAppearance, timeStamping);
					}
				}
			else {
				throw new Exception("Sign type must be 'single' or 'multiple only'");
			}
			
			System.out.println("Complete");
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
	}

}
