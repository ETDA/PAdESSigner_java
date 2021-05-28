package pkcs;

/**
 * The class of PKCS 12 extends from IPKCSInstance
 * @author ETDA
 *
 */

public class PKCS12Instance extends IPKCSInstance {
	private String filePath, keyStorePassword;
	
	/**
	 * Class constructor
	 * @param filePath The path of KeyStore file (*.p12, *.pfx)
	 * @param password The password of KeyStore
	 */
	public PKCS12Instance(String filePath, String keyStorePassword) {
		setFilePath(filePath);
		setKeyStorePassword(keyStorePassword);
	}

	/**
	 * @return the filePath
	 */
	public String getFilePath() {
		return filePath;
	}

	/**
	 * @param filePath the filePath to set
	 * @throws NullPointerException 
	 */
	public void setFilePath(String filePath) throws NullPointerException {
		if (filePath == null) {
			throw new NullPointerException("FilePath password cannot be null");
		}
		this.filePath = filePath;
	}

	/**
	 * @return the password
	 */
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	/**
	 * @param password the password to set
	 */
	public void setKeyStorePassword(String keyStorePassword) throws NullPointerException {
		if (keyStorePassword == null) {
			throw new NullPointerException("KeyStore password cannot be null");
		}
		
		this.keyStorePassword = keyStorePassword;
	}
}
