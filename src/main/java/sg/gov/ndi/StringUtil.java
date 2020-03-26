package sg.gov.ndi;

class StringUtil {

	/**
	 * <p>
	 * Null & Empty String Checker
	 * </p>
	 * 
	 * @param value
	 *            the string value
	 * @return true or false
	 * @since 1.0
	 */
	static boolean isEmptyAndNull(String value) throws MyInfoException {

		if (value == null || "".equals(value)) {
			return true;
		}

		return false;

	}

}
