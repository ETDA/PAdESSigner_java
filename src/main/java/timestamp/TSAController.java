package timestamp;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.io.codec.Base64;
import com.itextpdf.io.util.SystemUtil;
import com.itextpdf.kernel.PdfException;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.ITSAInfoBouncyCastle;
//import com.itextpdf.signatures.SignUtils;
//import com.itextpdf.signatures.SignUtils;
import com.itextpdf.signatures.TSAClientBouncyCastle;

public class TSAController implements ITSAClient {
	 /**
     * The default value for the hash algorithm
     */
    public static final String DEFAULTHASHALGORITHM = "SHA-256";
    /**
     * The default value for the hash algorithm
     */
    public static final int DEFAULTTOKENSIZE = 4096;
    /**
     * The Logger instance.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(TSAClientBouncyCastle.class);
    /**
     * URL of the Time Stamp Authority
     */
    protected String tsaURL;
    /**
     * TSA Username
     */
    protected String tsaUsername;
    /**
     * TSA password
     */
    protected String tsaPassword;
    /**
     * An interface that allows you to inspect the timestamp info.
     */
    protected ITSAInfoBouncyCastle tsaInfo;
    /**
     * Estimate of the received time stamp token
     */
    protected int tokenSizeEstimate;
    /**
     * Hash algorithm
     */
    protected String digestAlgorithm;

    /**
     * TSA request policy
     */
    private String tsaReqPolicy;
    
    private String _certificateUrl;
    private char[] _certificatePassword;

    /**
     * Creates an instance of a TSAClient that will use BouncyCastle.
     *
     * @param url String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
     */
    public TSAController(String url) {
        this(url, null, null, DEFAULTTOKENSIZE, DEFAULTHASHALGORITHM);
    }

    /**
     * Creates an instance of a TSAClient that will use BouncyCastle.
     *
     * @param url      String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
     * @param username String - user(account) name
     * @param password String - password
     */
    public TSAController(String url, String username, String password) {
        this(url, username, password, 4096, DEFAULTHASHALGORITHM);
    }

    /**
     * Constructor.
     * Note the token size estimate is updated by each call, as the token
     * size is not likely to change (as long as we call the same TSA using
     * the same imprint length).
     *
     * @param url           String - Time Stamp Authority URL (i.e. "http://tsatest1.digistamp.com/TSA")
     * @param username      String - user(account) name
     * @param password      String - password
     * @param tokSzEstimate int - estimated size of received time stamp token (DER encoded)
     */
    public TSAController(String url, String username, String password, int tokSzEstimate, String digestAlgorithm) {
        this.tsaURL = url;
        this.tsaUsername = username;
        this.tsaPassword = password;
        this.tokenSizeEstimate = tokSzEstimate;
        this.digestAlgorithm = digestAlgorithm;
    }
    
    public TSAController(String url, String certificatePath, char[] certificatePassword) {
    	this.tsaURL = url;
    	this._certificateUrl = certificatePath;
    	this._certificatePassword = certificatePassword;
    }

    /**
     * @param tsaInfo the tsaInfo to set
     */
    public void setTSAInfo(ITSAInfoBouncyCastle tsaInfo) {
        this.tsaInfo = tsaInfo;
    }

    /**
     * Get the token size estimate.
     * Returned value reflects the result of the last succesfull call, padded
     *
     * @return an estimate of the token size
     */
    @Override
    public int getTokenSizeEstimate() {
        return tokenSizeEstimate;
    }

    /**
     * Gets the TSA request policy that will be used when retrieving timestamp token.
     *
     * @return policy id, or <code>null</code> if not set
     */
    public String getTSAReqPolicy() {
        return tsaReqPolicy;
    }

    /**
     * Sets the TSA request policy that will be used when retrieving timestamp token.
     *
     * @param tsaReqPolicy policy id
     */
    public void setTSAReqPolicy(String tsaReqPolicy) {
        this.tsaReqPolicy = tsaReqPolicy;
    }

    /**
     * Gets the MessageDigest to digest the data imprint
     *
     * @return the digest algorithm name
     */
    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return new TSAMessageDigest().getMessageDigest(digestAlgorithm);
    }

    /**
     * Get RFC 3161 timeStampToken.
     * Method may return null indicating that timestamp should be skipped.
     *
     * @param imprint data imprint to be time-stamped
     * @return encoded, TSA signed data of the timeStampToken
     * @throws IOException
     * @throws TSPException
     */
    public byte[] getTimeStampToken(byte[] imprint) throws IOException, TSPException {
        byte[] respBytes = null;
        // Setup the time stamp request
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        if (tsaReqPolicy != null && tsaReqPolicy.length() > 0) {
            tsqGenerator.setReqPolicy(tsaReqPolicy);
        }
        // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
        
        //2.16.840.1.101.3.4.2.1
        BigInteger nonce = BigInteger.valueOf(SystemUtil.getTimeBasedSeed());
        //TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigest(digestAlgorithm)), imprint, nonce);
        TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), imprint, nonce);
        byte[] requestBytes = request.getEncoded();

        // Call the communications layer
        respBytes = getTSAResponse(requestBytes);

        // Handle the TSA response
        TimeStampResponse response = new TimeStampResponse(respBytes);

        // validate communication level attributes (RFC 3161 PKIStatus)
        response.validate(request);
        PKIFailureInfo failure = response.getFailInfo();
        int value = (failure == null) ? 0 : failure.intValue();
        if (value != 0) {
            // @todo: Translate value of 15 error codes defined by PKIFailureInfo to string
            throw new PdfException(PdfException.InvalidTsa1ResponseCode2).setMessageParams(tsaURL, String.valueOf(value));
        }
        // @todo: validate the time stap certificate chain (if we want
        //        assure we do not sign using an invalid timestamp).

        // extract just the time stamp token (removes communication status info)
        TimeStampToken tsToken = response.getTimeStampToken();
        if (tsToken == null) {
            throw new PdfException(PdfException.Tsa1FailedToReturnTimeStampToken2).setMessageParams(tsaURL, response.getStatusString());
        }
        TimeStampTokenInfo tsTokenInfo = tsToken.getTimeStampInfo(); // to view details
        byte[] encoded = tsToken.getEncoded();

        LOGGER.info("Timestamp generated: " + tsTokenInfo.getGenTime());
        if (tsaInfo != null) {
            tsaInfo.inspectTimeStampTokenInfo(tsTokenInfo);
        }
        // Update our token size estimate for the next call (padded to be safe)
        this.tokenSizeEstimate = encoded.length + 32;
        return encoded;
    }

    /**
     * Get timestamp token - communications layer
     *
     * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
     * @throws IOException
     */
    protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {
        // Setup the TSA connection
        TsaResponse response = getTsaResponseForUserRequest(tsaURL, requestBytes, tsaUsername, tsaPassword);
        // Get TSA response as a byte array
        InputStream inp = response.tsaResponseStream;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }
        byte[] respBytes = baos.toByteArray();

        if (response.encoding != null && response.encoding.toLowerCase().equals("base64".toLowerCase())) {
            respBytes = Base64.decode(new String(respBytes, "US-ASCII"));
        }
        return respBytes;
    }
    
    static class TsaResponse {
        String encoding;
        InputStream tsaResponseStream;
    }
    
    private TsaResponse getTsaResponseForUserRequest(String tsaUrl, byte[] requestBytes, String tsaUsername, String tsaPassword) throws IOException {
    	try {
    		KeyStore ks = KeyStore.getInstance("PKCS12");
        	FileInputStream fis = new FileInputStream(_certificateUrl);
        	ks.load(fis, _certificatePassword);
        	//KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        	KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        	kmf.init(ks, _certificatePassword);
        	/*
        	TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        	tmf.init(ks);
        	*/
        	
        	SSLContext sc = SSLContext.getInstance("TLS");
        	sc.init(kmf.getKeyManagers(), null, new SecureRandom());
        	SSLSocketFactory sf = sc.getSocketFactory();
        	
        	URL url = new URL(tsaUrl);
            //URLConnection tsaConnection;
            HttpsURLConnection tsaConnection;

            tsaConnection = (HttpsURLConnection) url.openConnection();
            tsaConnection.setSSLSocketFactory(sf);
            tsaConnection.setConnectTimeout(0);
            
            tsaConnection.setDoInput(true);
            tsaConnection.setDoOutput(true);
            tsaConnection.setUseCaches(false);
            tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
            //tsaConnection.setRequestProperty("Content-Transfer-Encoding", "base64");
            tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
            
            tsaConnection.connect();
            
            OutputStream out = tsaConnection.getOutputStream();
            out.write(requestBytes);
            out.close();

            TsaResponse response = new TsaResponse();
            response.tsaResponseStream = tsaConnection.getInputStream();
            response.encoding = tsaConnection.getContentEncoding();
            return response;
        	
    	} catch (Exception e) {
    		e.printStackTrace();
    		throw new PdfException(PdfException.FailedToGetTsaResponseFrom1).setMessageParams(tsaUrl);
    	}
    	
    	/*
        URL url = new URL(tsaUrl);
        //URLConnection tsaConnection;
        HttpsURLConnection tsaConnection;

        tsaConnection = (HttpsURLConnection) url.openConnection();
        tsaConnection.setSSLSocketFactory(sf);
        tsaConnection.setConnectTimeout(0);
        
        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        //tsaConnection.setRequestProperty("Content-Transfer-Encoding", "base64");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
        */
/*
        if ((tsaUsername != null) && !tsaUsername.equals("") ) {
            String userPassword = tsaUsername + ":" + tsaPassword;
            tsaConnection.setRequestProperty("Authorization", "Basic " +
                    Base64.encodeBytes(userPassword.getBytes(StandardCharsets.UTF_8), Base64.DONT_BREAK_LINES));
        }
        */
        /*
        try {
        	if ((_certificateUrl != null) && (_certificatePassword != null)) {
            	KeyStore ks = KeyStore.getInstance("PKCS12");
            	FileInputStream fis = new FileInputStream(_certificateUrl);
            	ks.load(fis, _certificatePassword);
            	KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            	kmf.init(ks, _certificatePassword);
            	SSLContext sc = SSLContext.getInstance("TLS");
            	sc.init(kmf.getKeyManagers(), null, null);
            	
            	
            	 //((HttpsURLConnection)tsaConnection).setSSLSocketFactory(sc.getSocketFactory());
            	
            	
            	
            }
        } catch (Exception ex) {
        	throw new PdfException(PdfException.FailedToGetTsaResponseFrom1).setMessageParams(tsaUrl);
        }
        */
        
        
        /*
        OutputStream out = tsaConnection.getOutputStream();
        out.write(requestBytes);
        out.close();

        TsaResponse response = new TsaResponse();
        response.tsaResponseStream = tsaConnection.getInputStream();
        response.encoding = tsaConnection.getContentEncoding();
        return response;
        */
    }
}
