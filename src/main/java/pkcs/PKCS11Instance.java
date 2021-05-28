package pkcs;

/**
 * The class of PKCS 11 extends from IPKCSInstance
 * @author ETDA
 *
 */

public class PKCS11Instance extends IPKCSInstance {
	private String libraryPath, keyStorePassword;
	private String tokenName;
	private String pin;
	private int slot;
	private String searchPhase;
	
	/**
	 * The class constructor
	 * @param tokenName The name of PKCS11 token
	 * @param libraryPath The path of library class file (.dll)
	 * @param pin The pin of Token
	 * @param keyStorePassword The password of KeyStore
	 * @param searchPhase The search phase, use to find certificate in PKCS11
	 */
	public PKCS11Instance(String tokenName, String libraryPath, String pin, String keyStorePassword, String searchPhase) {
		setTokenName(tokenName);
		setLibraryPath(libraryPath);
		setPin(pin);
		setKeyStorePassword(keyStorePassword);
		setSearchPhase(searchPhase);
	}
	
	/**
	 * 
	 * @param tokenName The name of PKCS11 token
	 * @param libraryPath The path of library class file (.dll)
	 * @param slot The slot of connected PKCS11
	 * @param pin The pin of Token
	 * @param keyStorePassword The password of KeyStore
	 * @param searchPhase The search phase, use to find certificate in PKCS11
	 */
	public PKCS11Instance(String tokenName, String libraryPath, int slot, String pin, String keyStorePassword, String searchPhase) {
		setTokenName(tokenName);
		setLibraryPath(libraryPath);
		setSlot(slot);
		setPin(pin);
		setKeyStorePassword(keyStorePassword);
		setSearchPhase(searchPhase);
	}
	
	/**
	 * @return the libraryPath
	 */
	public String getLibraryPath() {
		return libraryPath;
	}
	/**
	 * @param libraryPath the libraryPath to set
	 */
	public void setLibraryPath(String libraryPath) {
		this.libraryPath = libraryPath;
	}
	/**
	 * @return the tokenName
	 */
	public String getTokenName() {
		return tokenName;
	}
	/**
	 * @param tokenName the tokenName to set
	 */
	public void setTokenName(String tokenName) {
		this.tokenName = tokenName;
	}
	/**
	 * @return the password
	 */
	public String getPin() {
		return pin;
	}
	/**
	 * @param password the password to set
	 */
	public void setPin(String pin) {
		this.pin = pin;
	}
	/**
	 * @return the slot
	 */
	public int getSlot() {
		return slot;
	}
	/**
	 * @param slot the slot to set
	 */
	public void setSlot(int slot) {
		this.slot = slot;
	}
	
	/**
	 * @return the keyStorePassword
	 */
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	/**
	 * @param keyStorePassword the keyStorePassword to set
	 */
	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	/**
	 * @return the searchPhase
	 */
	public String getSearchPhase() {
		return searchPhase;
	}

	/**
	 * @param searchPhase the searchPhase to set
	 */
	public void setSearchPhase(String searchPhase) {
		this.searchPhase = searchPhase;
	}
}
