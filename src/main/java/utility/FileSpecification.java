package utility;

public class FileSpecification {
	private String fileNameWithoutExtension, fileNameWithExtension, fileExtension, fullFilePath;

	/**
	 * @return the fileNameWithoutExtension
	 */
	public String getFileNameWithoutExtension() {
		return fileNameWithoutExtension;
	}

	/**
	 * @param fileNameWithoutExtension the fileNameWithoutExtension to set
	 */
	public void setFileNameWithoutExtension(String fileNameWithoutExtension) {
		this.fileNameWithoutExtension = fileNameWithoutExtension;
	}

	/**
	 * @return the fileNameWithExtension
	 */
	public String getFileNameWithExtension() {
		return fileNameWithExtension;
	}

	/**
	 * @param fileNameWithExtension the fileNameWithExtension to set
	 */
	public void setFileNameWithExtension(String fileNameWithExtension) {
		this.fileNameWithExtension = fileNameWithExtension;
	}

	/**
	 * @return the fileExtension
	 */
	public String getFileExtension() {
		return fileExtension;
	}

	/**
	 * @param fileExtension the fileExtension to set
	 */
	public void setFileExtension(String fileExtension) {
		this.fileExtension = fileExtension;
	}

	/**
	 * @return the fullFilePath
	 */
	public String getFullFilePath() {
		return fullFilePath;
	}

	/**
	 * @param fullFilePath the fullFilePath to set
	 */
	public void setFullFilePath(String fullFilePath) {
		this.fullFilePath = fullFilePath;
	}

}
