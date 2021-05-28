package timestamp;
/**
 * TimeStamp class
 * @author ETDA
 *
 */
public class TimeStamp {
	private TSAAuthenticationType tsaAuthenticationType;
	private TimeStampType timeStampType;
	private String username, password, certificatePath, URL;
	
	/**
	 * 
	 * @param timeStampType
	 */
	public TimeStamp(TimeStampType timeStampType) {
		setTimeStampingType(timeStampType);
	}
	
	/**
	 * 
	 * @param timeStampType
	 * @param tsaAuthenticationType
	 */
	public TimeStamp(TimeStampType timeStampType, String url, TSAAuthenticationType tsaAuthenticationType) {
		setTimeStampingType(timeStampType);
		setTSAAuthenticationType(tsaAuthenticationType);
		setURL(url);
	}
	
	/**
	 * 
	 * @param timeStampType
	 * @param tsaAuthenticationType
	 * @param username
	 * @param password
	 */
	public TimeStamp(TimeStampType timeStampType, String url, TSAAuthenticationType tsaAuthenticationType, String username, String password) {
		setTimeStampingType(timeStampType);
		setURL(url);
		setTSAAuthenticationType(tsaAuthenticationType);
		setUsername(username);
		setPassword(password);
	}
	/*
	public TimeStamping(TimeStampingType timeStampType, TSAAuthenticationType tsaAuthenticationType, String certificatePath, String password) {
		setTimeStampingType(timeStampType);
		setTSAAuthenticationType(tsaAuthenticationType);
		setCertificatePath(certificatePath);
		setPassword(password);
	}
	*/
	
	/**
	 * @return the timeStampType
	 */
	public TimeStampType getTimeStampingType() {
		return timeStampType;
	}
	/**
	 * @param timeStampType the timeStampType to set
	 */
	public void setTimeStampingType(TimeStampType timeStampType) {
		this.timeStampType = timeStampType;
	}
	/**
	 * @return the tsaAuthenticationType
	 */
	public TSAAuthenticationType getTSAAuthenticationType() {
		return tsaAuthenticationType;
	}
	/**
	 * @param tsaAuthenticationType the tsaAuthenticationType to set
	 */
	public void setTSAAuthenticationType(TSAAuthenticationType tsaAuthenticationType) {
		this.tsaAuthenticationType = tsaAuthenticationType;
	}
	/**
	 * @return the username
	 */
	public String getUsername() {
		return username;
	}
	/**
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}
	/**
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}
	/**
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	/**
	 * @return the certificatePath
	 */
	public String getCertificatePath() {
		return certificatePath;
	}
	/**
	 * @param certificatePath the certificatePath to set
	 */
	public void setCertificatePath(String certificatePath) {
		this.certificatePath = certificatePath;
	}
	/**
	 * @return the uRL
	 */
	public String getURL() {
		return URL;
	}
	/**
	 * @param uRL the uRL to set
	 */
	public void setURL(String uRL) {
		URL = uRL;
	}
	
	

}
