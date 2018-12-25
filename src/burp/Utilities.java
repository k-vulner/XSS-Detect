package burp;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;

public class Utilities {
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
	private static IBurpCollaboratorClientContext collab;
	public static HashMap<String, RandomStrLog> hashmapRequestIdWithStr = new HashMap<String, RandomStrLog>();
    public Utilities(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        collab = callbacks.createBurpCollaboratorClientContext();
    }
    public static void out(String message) {
        stdout.println(message);
    }
    public static void err(String message) {
        stderr.println(message);
    }
	public static String randomStr(int requestId, String Argv) {
		String random = collab.generatePayload(false);
		hashmapRequestIdWithStr.put(random, new RandomStrLog(requestId, Argv));
		return random;

	}
	public static class RandomStrLog {
		int requestId;
		String Argv;

		public RandomStrLog(int requestId, String argv) {

			this.requestId = requestId;
			this.Argv = argv;
		}

	}
	public static String printStackTraceToString(Throwable t) {
	    StringWriter sw = new StringWriter();
	    t.printStackTrace(new PrintWriter(sw, true));
	    return sw.getBuffer().toString();
	}

}
