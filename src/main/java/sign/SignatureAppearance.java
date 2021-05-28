package sign;

public class SignatureAppearance {
	
	private float x, y, width, height;
	private int pageNumber;
	private String signatureFieldName;
	private String reason, location;
	private SignatureLevel signatureLevel;
	private SignaturePattern signaturePattern;
	private String signatureImage;
	private SignatureVisibility signatureVisibility;
	
	/**
	 * Get signature coordinate 'X'
	 * @return float
	 */
	public float getX() {
		return x;
	}
	
	/**
	 * Set signature coordinate 'X'
	 * @param x
	 */
	public void setX(float x) {
		this.x = x;
	}
	
	/**
	 * Get signature coordinate 'Y'
	 * @return float 
	 */
	public float getY() {
		return y;
	}
	
	/**
	 * Set signature coordinate 'Y'
	 * @param y
	 */
	public void setY(float y) {
		this.y = y;
	}
	
	/**
	 * Get width of signature
	 * @return float
	 */
	public float getWidth() {
		return width;
	}
	
	/**
	 * Set width of signature
	 * @param width
	 */
	public void setWidth(float width) {
		this.width = width;
	}
	
	/**
	 * Get height of signature
	 * @return float
	 */
	public float getHeight() {
		return height;
	}
	
	/**
	 * Set height of signature
	 * @param height
	 */
	public void setHeight(float height) {
		this.height = height;
	}
	
	/**
	 * Get page number
	 * @return int
	 */
	public int getPageNumber() {
		return pageNumber;
	}
	
	/**
	 * Set page number
	 * @param pageNumber
	 */
	public void setPageNumber(int pageNumber) {
		this.pageNumber = pageNumber;
	}
	
	/**
	 * Get signature field name
	 * @return
	 */
	public String getSignatureFieldName() {
		return signatureFieldName;
	}
	
	/**
	 * Set signature field name
	 * @param signatureFieldName
	 */
	public void setSignatureFieldName(String signatureFieldName) {
		this.signatureFieldName = signatureFieldName;
	}
	
	/**
	 * Get reason
	 * @return String
	 */
	public String getReason() {
		return reason;
	}
	
	/**
	 * Set reason
	 * @param reason
	 */
	public void setReason(String reason) {
		this.reason = reason;
	}
	
	/**
	 * Get location
	 * @return String
	 */
	public String getLocation() {
		return location;
	}
	
	/**
	 * Set location
	 * @param location
	 */
	public void setLocation(String location) {
		this.location = location;
	}

	/**
	 * Get sinature level
	 * @return the signatureLevel
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * Set signature level
	 * @param signatureLevel the signatureLevel to set
	 */
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Get signature image
	 * @return the signatureImage
	 */
	public String getSignatureImage() {
		return signatureImage;
	}

	/**
	 * Set signature image
	 * @param signatureImage the signatureImage to set
	 */
	public void setSignatureImage(String signatureImage) {
		this.signatureImage = signatureImage;
	}

	/**
	 * Get signature pattern
	 * @return the signaturePattern
	 */
	public SignaturePattern getSignaturePattern() {
		return signaturePattern;
	}

	/**
	 * Set signature pattern
	 * @param signaturePattern the signaturePattern to set
	 */
	public void setSignaturePattern(SignaturePattern signaturePattern) {
		this.signaturePattern = signaturePattern;
	}

	/**
	 * Get signature visibility
	 * @return the stampType
	 */
	public SignatureVisibility getSignatureVisibility() {
		return signatureVisibility;
	}

	/**
	 * Set signature visibility
	 * @param stampType the stampType to set
	 */
	public void setSignatureVisibility(SignatureVisibility signatureVisibility) {
		this.signatureVisibility = signatureVisibility;
	}

}
